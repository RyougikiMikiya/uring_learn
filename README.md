# io_uring初探

## 前言

和网卡收包一样，硬件性能越来越强的今天，操作系统的传统API已经成了非常大的瓶颈。比如write虽然不是阻塞操作，但是依然会陷入内核然后巴拉巴拉搞一堆，这个就看看文档就知道了。
同样的现在流行的SPDK也是把dpdk搬到了存储上，SPDK我还没用过不做介绍。而异步IO一直是Linux的痛点，AIO风评非常的差，随便一搜都是吐槽（没在项目中用过，不做评论。。）。所以io_uring横空出世就是为了解决目前这个问题。他需要高内核版本支持，并且每个发行版本可能还不一样。但是全是5.x+，否则`io_uring_queue_init`会返回-ENOSYS，也就是没有这个系统调用。网上的中文文章有，但是看着很头痛。。。还是看看原生的英文教学吧家人们。<https://unixism.net/loti/tutorial/index.html> loti的缩写是lord of the io_uring。非常的牛逼~~

## io_uring和liburing

简单的说，io_uring的原生api非常的复杂，虽然他只有三个系统调用，但是用好是非常困难的。所以我们的大神亲切的为我们封装了一个对调用者友好的库，那就是liburing。在实际中我们只需要调用liburing的接口就可以相对轻松的实现异步io操作了。liburing几乎封装了所有的io操作，不仅限于磁盘还有网络。官方教程中还有一个echo server后面有兴趣可以继续研究。

## 环境搭建

WSL2：翻微软的Github release可知，WSL2直到5.10.60.1-microsoft-standard-WSL2才支持io_uring功能。其他的平台暂时没测
WSL2可以去 <https://www.catalog.update.microsoft.com/Search.aspx?q=wsl>下载update然后一键升级，很方便
而liburing的地址是<https://github.com/axboe/liburing> 克隆后make && make install即可

## 性能表现

测试文件：39M test.pcap

测试代码: uring_test.cpp

```plain
iovecs size 113411
total pkts: 56705
writev Elapsed: 19414 clock
write Elapsed: 128066 clock
fstream Elapsed: 43908 clock
uring1 Elapsed: 827 clock
uring2 Elapsed: 1894 clock
```

可以看到顺序写的性能非常强劲

## 基本原理

岂敢岂敢，只能写一下使用心得。可能还有误

在liburing中，我们要使用到两个队列来完成我们的异步操作。一个叫Submit Queue，一个叫Completion Queue。从字面意思可以很简单的看出，一个是提交队列，一个是完成队列。这两个队列是来自于我们初始化的一个uring。当用户要sq提交异步操作并确认后便把工作交给了内核来处理，只需要在“合适”的时机来检查一下cq里面是有完成事件即可。你可能会问检测（wait）操作同样要阻塞那异步的价值在哪里呢？但是参考测试代码和结果你就能发现原来传统io耗费了太多的时间导致异步操作的性能提升了十倍不止（仅本用例）。

## SQE与Submit

```c
/* Init a uring */
...
/* Get an SQE */
struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
/* Setup a readv operation */
io_uring_prep_readv(sqe, file_fd, fi->iovecs, blocks, 0);
/* Set user data */
io_uring_sqe_set_data(sqe, fi);
/* Finally, submit the request */
io_uring_submit(ring);
```

必须值得注意的是，每一次io操作必须绑定一个sqe，一次submit可以同时submit多次io操作。同时最大支持提交的io操作取决于初始化时指定的队列大小`io_uring_queue_init`的第一次参数。笔者最开始学习时在一个sqe上反复提交了多个writev操作最后发现只执行了一次在这里踩了大坑，所以记得多看文档比如

`io_uring_submit`：

```
Submits the SQEs acquired via io_uring_get_sqe() to the kernel. You can call this once after you have called io_uring_get_sqe() multiple times to set up multiple I/O requests.
```

`io_uring_get_sqe`:

```
This function returns a submission queue entry that can be used to submit an I/O operation. You can call this function multiple times to queue up I/O requests before calling io_uring_submit() to tell the kernel to process your queued requests.
```

## CQE与Completion

```c
int get_completion_and_print(struct io_uring *ring) {
    struct io_uring_cqe *cqe;
    int ret = io_uring_wait_cqe(ring, &cqe);

    if (ret < 0) {
        perror("io_uring_wait_cqe");
        return 1;
    }

    if (cqe->res < 0) { // io操作的返回值
        /* The system call invoked asynchonously failed */
        return 1;
    }

    /* Retrieve user data from CQE */
    struct file_info *fi = io_uring_cqe_get_data(cqe);
    /* process this request here */

    /* Mark this completion as seen */
    io_uring_cqe_seen(ring, cqe);
    return 0;
}
```

对于每一个wait的操作，在处理完毕后，必须调用seen或者类似的函数来显示的清空他。不然下次检测还会检测到他。我在程序中还调用了诸如`io_uring_submit_and_wait`这样一气呵成的代码，有点类似rust中`async+await?`的感觉吧。

## 总结

个人粗略的学习之后认为，异步开发比同步在代码设计上难度确实会大很多，主要就是sqe和cqe的管理，sqe满和不满时不同的操作，cqe返回时的状态检测等等。但是性能提升应该是肉眼可见的。

一个线程在sqe可以获取时，submit一个已经组装好的iovecs。而sqe不能获取时或者没有数据时，则组装数据。另一个线程则纯粹的等待cqe，做返回与善后处理。
