#include <array>
#include <cstddef>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <sys/uio.h>
#include <vector>
#include <algorithm>

#include <cassert>
#include <limits.h>
#include <pcap.h>
#include <cstring>
#include <cstdlib>
#include <memory.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <liburing.h>

const static pcap_file_header std_pcap_hdr = {.magic = 0xa1b2c3d4,
                                              .version_major = 2,
                                              .version_minor = 4,
                                              .thiszone = 0,
                                              .sigfigs = 0,
                                              .snaplen = 0x00040000,
                                              .linktype = 1};

using namespace std;

const int iov_max = sysconf(_SC_IOV_MAX);

void test01(int argc, char **argv)
{
    string errBuf;
    errBuf.reserve(PCAP_ERRBUF_SIZE);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_dumper_t *dumper = nullptr;
    pcap_t *pcap = pcap_open_offline(argv[1], errbuf);
    if (!pcap)
    {
        cout << errBuf << endl;
        goto exit;
    }

    dumper = pcap_dump_open(pcap, "test.pcap");
    if (!dumper)
    {
        perror("pcap_dump_open");
        goto exit;
    }

    pcap_loop(pcap, 0, pcap_dump, (u_char *)dumper);

    pcap_dump_close(dumper);

exit:
    return;
}

struct my_pcap_sf_pkthdr
{
    bpf_int32 tv_sec;   /* seconds */
    bpf_int32 tv_usec;  /* microseconds */
    bpf_u_int32 caplen; /* length of portion present */
    bpf_u_int32 len;    /* length of this packet (off wire) */
    my_pcap_sf_pkthdr(const struct pcap_pkthdr *hdr)
        : len(hdr->len), caplen(hdr->caplen), tv_sec((bpf_int32)hdr->ts.tv_sec),
          tv_usec(bpf_int32(hdr->ts.tv_usec)) {}
};

using pkthdr_vec = std::vector<my_pcap_sf_pkthdr>;
using pktdata = std::vector<u_char>;
using pktdata_vec = std::vector<pktdata>;

pkthdr_vec pkthdrs;
pktdata_vec pktdatas;

void my_handler(u_char *user, const struct pcap_pkthdr *hdr,
                const u_char *data)
{
    pcap_dump(user, hdr, data);
    pkthdrs.emplace_back(hdr);
    pktdatas.emplace_back(pktdata(data, data + hdr->caplen));
}

std::vector<iovec> iovecs;

/*
      i = 0, j = 1,2
      i = 1, j = 3,4
      i = 2, j = 5,6
 */

void prepare_iovec()
{
    iovecs.clear();
    assert(pkthdrs.size() == pktdatas.size());
    // int cnt = min(pkthdrs.size(), pktdatas.size());
    int cnt = pkthdrs.size();
    iovecs.reserve(cnt * 2 + 1);

    iovecs.push_back(
        {.iov_base = (void *)&std_pcap_hdr,
         .iov_len = sizeof std_pcap_hdr});
    for (int i = 0; i != cnt; i++)
    {
        iovecs.push_back({.iov_base = (void *)&pkthdrs[i],
                          .iov_len = sizeof(my_pcap_sf_pkthdr)});

        iovecs.push_back({.iov_base = (void *)pktdatas[i].data(),
                          .iov_len = pktdatas[i].size()});
    }
    cout << "iovecs size " << iovecs.size() << endl;
}

void write_pcap_by_writev(int fd)
{
    assert(fd >= 0);

    int writed = 0, rest = iovecs.size();
    do
    {
        int per = rest > IOV_MAX ? IOV_MAX : rest;
        int ret = writev(fd, iovecs.data() + writed, per);
        if (ret < 0)
        {
            perror("writev\n");
            break;
        }
        writed += per;
        rest -= IOV_MAX;
    } while (rest > 0);
}

void write_pcap_by_write(int fd2)
{
    assert(fd2 >= 0);

#if 0
    int ret = write(fd2, &std_pcap_hdr, sizeof std_pcap_hdr);
    assert(ret > 0);

    for (int i = 0; i < pkthdrs.size(); i++)
    {
        ret = write(fd2, &pkthdrs[i], sizeof(my_pcap_sf_pkthdr));
        assert(ret > 0);
        int len1 = pktdatas[i].size();
        ret = write(fd2, pktdatas[i].data(), len1);
        assert(ret > 0);
    }
#else
    for_each(iovecs.begin(), iovecs.end(), [fd2](auto & iovec){
        int ret = write(fd2, iovec.iov_base, iovec.iov_len);
        assert(ret > 0);
    });
#endif
}

void write_pcap_by_fstream(ofstream &f1)
{
    assert(f1.is_open());

    f1.write((const char *)&std_pcap_hdr, sizeof std_pcap_hdr);

    for (int i = 0; i < pkthdrs.size(); i++)
    {
        f1.write((const char *)&pkthdrs[i], sizeof(my_pcap_sf_pkthdr)).write((const char *)pktdatas[i].data(), pktdatas[i].size());
        if (f1.bad())
        {
            assert(false);
        }
    }
}

void write_pcap_by_uring_1(int fd)
{
    assert(fd >= 0);
    int ret;
    struct io_uring ring;
    int cur_offset = 0;

    uint entries = 4;

    ret = io_uring_queue_init(entries, &ring, 0);
    if (ret < 0)
    {
        perror("io_uring_queue_init !!");
        return;
    }

    iovec *tmp = iovecs.data();
    int size = iovecs.size();

    struct io_uring_cqe *cqe = nullptr;
    int writed = 0, rest = iovecs.size();
    int per = rest > IOV_MAX ? IOV_MAX : rest;
    int submited = 0;

    do
    {
        auto sqe = io_uring_get_sqe(&ring);
        if (!sqe)
        {
#if 0
            ret = io_uring_submit(&ring);
            printf("io_uring_submit ret %d\n", ret);
            int pending = ret;
            for (int i = pending; i != 0; i--)
            {
                ret = io_uring_wait_cqe(&ring, &cqe);
                if (ret < 0)
                {
                    fprintf(stderr, "io_uring_wait_cqe: %s\n",
                            strerror(-ret));
                    return;
                }
                io_uring_cqe_seen(&ring, cqe);
            }
#else
            ret = io_uring_submit_and_wait(&ring, entries);
            /*
                如果ret 不等于 entries...要怎么办？应该是again
             */
            assert(ret == entries);
            io_uring_cq_advance(&ring, ret);
#endif
            submited = 0;
            continue;
        }
        int per = rest > IOV_MAX ? IOV_MAX : rest;
        /* 
            这里必须要自己去算offset，不能用-1。更不能用0！！-1代表append。0就永远在开头写
         */
        io_uring_prep_writev(sqe, fd, iovecs.data() + writed, per, cur_offset);
        for (int i = writed; i < writed + per; i++)
        {
            cur_offset += iovecs[i].iov_len;
        }
        writed += per;
        rest -= per;
        submited++;
    } while (rest > 0);

    ret = io_uring_submit_and_wait(&ring, submited);
    assert(ret == submited);
    io_uring_cq_advance(&ring, ret);

    io_uring_queue_exit(&ring);

    return;
}

void write_pcap_by_uring_2(int fd)
{
    assert(fd >= 0);

    io_uring ring;
    int preped = 0;
    uint entries = 64;

    int ret = io_uring_queue_init(entries, &ring, 0);
    if (ret < 0)
    {
        cout << ret << endl;
        perror("io_uring_queue_init !!");
        return;
    }

    int offset = 0;

    for (int i = 0; i < iovecs.size(); i++) 
    {
        auto sqe = io_uring_get_sqe(&ring);
        if(!sqe) 
        {
            ret = io_uring_submit_and_wait(&ring, preped);
            assert(ret == entries);
            io_uring_cq_advance(&ring, ret);
            preped = 0;
            sqe = io_uring_get_sqe(&ring);
            assert(sqe);
        }
        io_uring_prep_write(sqe, fd, iovecs[i].iov_base, iovecs[i].iov_len, offset);
        preped++;
        offset += iovecs[i].iov_len;
    }
    ret = io_uring_submit_and_wait(&ring, preped);
    io_uring_cq_advance(&ring, ret);

    io_uring_queue_exit(&ring);
}

void cq_clear_test()
{
    io_uring ring;
    int ret = io_uring_queue_init(1, &ring, 0);

    io_uring_cqe *cqe;

    for (int i = 0; i < 10000; i++){
        auto sqe = io_uring_get_sqe(&ring);
        assert(sqe);
        auto sqe2 = io_uring_get_sqe(&ring);
        assert(!sqe2);
        io_uring_prep_write(sqe, STDOUT_FILENO, "hello world\n", 13, 0);
        io_uring_submit_and_wait(&ring, 1);
        /* 
            这里如果不调用去清空cq的状态，那么后面get sqe一样会失败的
         */
        // io_uring_cq_advance(&ring, 1);
    }

    io_uring_queue_exit(&ring);
}

int main(int argc, char **argv)
{
    string errBuf;
    errBuf.reserve(PCAP_ERRBUF_SIZE);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_dumper_t *dumper = nullptr;

    cout << "iov_max =" << iov_max << endl;
 
    pcap_t *pcap = pcap_open_offline(argv[1], errbuf);
    if (!pcap)
    {
        cout << "需要传一个pcap文件~" << errBuf << endl;
        return -1;
    }

    auto file = pcap_dump_open(pcap, "test_pcap_dump.pcap");
    pcap_loop(pcap, 0, my_handler, (u_char*)file);

    pcap_close(pcap);

    /*
        准备iovec数据
      */

    prepare_iovec();

    cout << "total pkts: " << pkthdrs.size() << endl;

    int fd = open("test_writev.pcap", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    clock_t tic1 = clock();
    write_pcap_by_writev(fd);
    clock_t tic2 = clock();
    close(fd);

    printf("writev Elapsed: %lu clock\n", tic2 - tic1);

    int fd2 = open("test_write.pcap", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    clock_t tic3 = clock();
    write_pcap_by_write(fd2);
    clock_t tic4 = clock();
    close(fd2);

    printf("write Elapsed: %lu clock\n", tic4 - tic3);

    ofstream f1("test_fstream.pcap", ios::out | ios::binary | ios::trunc);
    clock_t tic5 = clock();
    write_pcap_by_fstream(f1);
    clock_t tic6 = clock();
    f1.close();

    printf("fstream Elapsed: %lu clock\n", tic6 - tic5);


    fd = open("test_uring_1.pcap", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    clock_t tic7 = clock();
    write_pcap_by_uring_1(fd);
    clock_t tic8 = clock();
    close(fd);

    printf("uring1 Elapsed: %lu clock\n", tic8 - tic7);

    fd = open("test_uring_2.pcap", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    clock_t tic9 = clock();
    write_pcap_by_uring_2(fd);
    clock_t tic10 = clock();
    close(fd);

    printf("uring2 Elapsed: %lu clock\n", tic10 - tic9);

exit:
    return 0;
}