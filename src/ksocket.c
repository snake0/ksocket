/* 
 * ksocket project
 * BSD-style socket APIs for kernel 2.6 developers
 * 
 * @2007-2008, China
 * @song.xian-guang@hotmail.com (MSN Accounts)
 * 
 * This code is licenced under the GPL
 * Feel free to contact me if any questions
 *
 * @2017
 * Hardik Bagdi (hbagdi1@binghamton.edu)
 * Changes for Compatibility with Linux 4.9 to use iov_iter
 * 
 */
#include <linux/module.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/in.h>
#include <net/sock.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include "ksocket.h"
//#include "nested.h"
//#include "sxgdebug.h"

#define KSOCKET_NAME	"ksocket"
#define KSOCKET_VERSION	"0.0.2"
#define KSOCKET_DESCPT	"BSD-style socket APIs for kernel 2.6 developers"
#define KSOCKET_AUTHOR	"msn : song.xian-guang@hotmail.com\n"\
						"blog: http://sxg.cublog.cn"
#define KSOCKET_DATE	"2008-05-15"

MODULE_AUTHOR(KSOCKET_AUTHOR);
MODULE_DESCRIPTION(KSOCKET_NAME"-"KSOCKET_VERSION"\n"KSOCKET_DESCPT);
MODULE_LICENSE("Dual BSD/GPL");

/*
static void (*origSk)(struct sock *sk, int bytes) = NULL;

static void yh_sk_data_ready(struct sock *sk, int bytes)
{
	if (origSk) {
		(*origSk)(sk, bytes);
	}

	wake_up_rcv();
	return;
}
*/

ksocket_t ksocket(int domain, int type, int protocol)
{
	struct socket *sk = NULL;
	int ret = 0;
	
	ret = sock_create(domain, type, protocol, &sk);
	if (ret < 0)
	{
		printk(KERN_INFO "sock_create failed\n");
		return NULL;
	}

	/*
	if (sk && sk->sk) {
		if (sk->sk->sk_data_ready) {
			origSk = sk->sk->sk_data_ready;
			sk->sk->sk_data_ready = yh_sk_data_ready;
		} else {
			printk(KERN_INFO "sk->sk->sk_data_ready is NULL\n");
		}
	} else {
		printk(KERN_INFO "sk or sk->sk is NULL\n");
	}
	*/
	
	printk("sock_create sk= 0x%p\n", sk);
	
	return sk;
}

int kbind(ksocket_t socket, struct sockaddr *address, int address_len)
{
	struct socket *sk;
	int ret = 0;

	sk = (struct socket *)socket;
	ret = sk->ops->bind(sk, address, address_len);
	printk("kbind ret = %d\n", ret);
	
	return ret;
}

int klisten(ksocket_t socket, int backlog)
{
	struct socket *sk;
	int ret;

	sk = (struct socket *)socket;
	
	if ((unsigned)backlog > SOMAXCONN)
		backlog = SOMAXCONN;
	
	ret = sk->ops->listen(sk, backlog);
	
	return ret;
}

int kconnect(ksocket_t socket, struct sockaddr *address, int address_len)
{
	struct socket *sk;
	int ret;

	sk = (struct socket *)socket;
	ret = sk->ops->connect(sk, address, address_len, 0/*sk->file->f_flags*/);
	
	return ret;
}

ksocket_t kaccept(ksocket_t socket, struct sockaddr *address, int *address_len)
{
	struct socket *sk;
	struct socket *new_sk = NULL;
	int ret;
	
	sk = (struct socket *)socket;

	printk("family = %d, type = %d, protocol = %d\n",
					sk->sk->sk_family, sk->type, sk->sk->sk_protocol);
	//new_sk = sock_alloc();
	//sock_alloc() is not exported, so i use sock_create() instead
	ret = sock_create(sk->sk->sk_family, sk->type, sk->sk->sk_protocol, &new_sk);
	if (ret < 0)
		return NULL;
	if (!new_sk)
		return NULL;
	
	new_sk->type = sk->type;
	new_sk->ops = sk->ops;
	
	ret = sk->ops->accept(sk, new_sk, 0 /*sk->file->f_flags*/);
	if (ret < 0)
		goto error_kaccept;
	
	if (address)
	{
		ret = new_sk->ops->getname(new_sk, address, address_len, 2);
		if (ret < 0)
			goto error_kaccept;
	}
	
	return new_sk;

error_kaccept:
	sock_release(new_sk);
	return NULL;
}

ssize_t krecv(ksocket_t socket, void *buffer, size_t length, int flags)
{
	struct socket *sk;
	struct msghdr msg;
	struct iovec iov;
	int ret;
#ifndef KSOCKET_ADDR_SAFE
	mm_segment_t old_fs;
#endif

	memset(&msg,0,sizeof(msg));
	sk = (struct socket *)socket;

	iov.iov_base = (void *)buffer;
	iov.iov_len = (__kernel_size_t)length;

	//type
	msg.msg_iter.type = READ;
	//address
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	//msg_iter
	msg.msg_iter.iov = &iov;
	msg.msg_iter.iov_offset = 0;
	msg.msg_iter.count = iov.iov_len;
	msg.msg_iter.nr_segs = 1;
	//control
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	/*
	 * msg.msg_iov->iov_base is declared as follows:
	 * void __user *iov_base;
	 * which means there is an user space pointer in 'msg'
	 * use set_fs(KERNEL_DS) to make the pointer safe to kernel space
	 */
#ifndef KSOCKET_ADDR_SAFE
	old_fs = get_fs();
	set_fs(KERNEL_DS);
#endif
	//hardik
	ret = sock_recvmsg(sk, &msg, flags);
#ifndef KSOCKET_ADDR_SAFE
	set_fs(old_fs);
#endif
	if (ret < 0)
		goto out_krecv;
	//ret = msg.msg_iov.iov_len;//?
	
out_krecv:
	return ret;

}

ssize_t ksend(ksocket_t socket, const void *buffer, size_t length, int flags)
{
	struct socket *sk;
	struct msghdr msg;
	struct iovec iov;
	int len;
#ifndef KSOCKET_ADDR_SAFE
	mm_segment_t old_fs;
#endif

	sk = (struct socket *)socket;

	iov.iov_base = (void *)buffer;
	iov.iov_len = (__kernel_size_t)length;

	//type
	msg.msg_iter.type = READ;
	//address
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	//msg_iter
	msg.msg_iter.iov = &iov;
	msg.msg_iter.iov_offset = 0;
	msg.msg_iter.count = iov.iov_len;
	msg.msg_iter.nr_segs = 1;
	//control
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	msg.msg_flags = flags;

#ifndef KSOCKET_ADDR_SAFE
	old_fs = get_fs();
	set_fs(KERNEL_DS);
#endif
	//hardik
	len = sock_sendmsg(sk, &msg);//?
#ifndef KSOCKET_ADDR_SAFE
	set_fs(old_fs);
#endif
	
	return len;//len ?
}

int kshutdown(ksocket_t socket, int how)
{
	struct socket *sk;
	int ret = 0;

	sk = (struct socket *)socket;
	if (sk)
		ret = sk->ops->shutdown(sk, how);
	
	return ret;
}

//TODO: ?
int kclose(ksocket_t socket)
{
	struct socket *sk;
	int ret;

	sk = (struct socket *)socket;
	ret = sk->ops->release(sk);

	if (sk)
		sock_release(sk);

	return ret;
}

ssize_t krecvfrom(ksocket_t socket, void * buffer, size_t length,
              int flags, struct sockaddr * address,
              int * address_len)
{
	struct socket *sk;
	struct msghdr msg;
	struct iovec iov;
	int len;
#ifndef KSOCKET_ADDR_SAFE
	mm_segment_t old_fs;
#endif

	sk = (struct socket *)socket;

	iov.iov_base = (void *)buffer;
	iov.iov_len = (__kernel_size_t)length;

	//type
	msg.msg_iter.type = READ;
	//address
	msg.msg_name = address;
	msg.msg_namelen = 128;
	//msg_iter
	msg.msg_iter.iov = &iov;
	msg.msg_iter.iov_offset = 0;
	msg.msg_iter.count = iov.iov_len;
	msg.msg_iter.nr_segs = 1;
	//control
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	
#ifndef KSOCKET_ADDR_SAFE
	old_fs = get_fs();
	set_fs(KERNEL_DS);
#endif
	//hardik
	len = sock_recvmsg(sk, &msg, flags);
#ifndef KSOCKET_ADDR_SAFE
	set_fs(old_fs);
#endif

	if (address)
	{
		*address_len = msg.msg_namelen;
	}
	
	return len;
}

ssize_t ksendto(ksocket_t socket, void *message, size_t length,
              int flags, const struct sockaddr *dest_addr,
              int dest_len)
{
	struct socket *sk;
	struct msghdr msg;
	struct iovec iov;
	int len;
#ifndef KSOCKET_ADDR_SAFE
	mm_segment_t old_fs;
#endif

	sk = (struct socket *)socket;

	iov.iov_base = (void *)message;
	iov.iov_len = (__kernel_size_t)length;

	//type
	msg.msg_iter.type = READ;
	//msg_iter
	msg.msg_iter.iov = &iov;
	msg.msg_iter.iov_offset = 0;
	msg.msg_iter.count = iov.iov_len;
	msg.msg_iter.nr_segs = 1;
	//control
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	msg.msg_flags = flags;
	if (dest_addr)
	{
		msg.msg_name = (void *)dest_addr;
		msg.msg_namelen = dest_len;
	}

#ifndef KSOCKET_ADDR_SAFE
	old_fs = get_fs();
	set_fs(KERNEL_DS);
#endif
	//hardik
	len = sock_sendmsg(sk, &msg);//?
#ifndef KSOCKET_ADDR_SAFE
	set_fs(old_fs);
#endif
	
	return len;//len ?
}

int kgetsockname(ksocket_t socket, struct sockaddr *address, int *address_len)
{
	struct socket *sk;
	int ret;
	
	sk = (struct socket *)socket;
	ret = sk->ops->getname(sk, address, address_len, 0);
	
	return ret;
}

int kgetpeername(ksocket_t socket, struct sockaddr *address, int *address_len)
{
	struct socket *sk;
	int ret;
	
	sk = (struct socket *)socket;
	ret = sk->ops->getname(sk, address, address_len, 1);
	
	return ret;
}

int ksetsockopt(ksocket_t socket, int level, int optname, void *optval, int optlen)
{
	struct socket *sk;
	int ret;
#ifndef KSOCKET_ADDR_SAFE
	mm_segment_t old_fs;
#endif

	sk = (struct socket *)socket;

#ifndef KSOCKET_ADDR_SAFE
	old_fs = get_fs();
	set_fs(KERNEL_DS);
#endif

	if (level == SOL_SOCKET)
		ret = sock_setsockopt(sk, level, optname, optval, optlen);
	else
		ret = sk->ops->setsockopt(sk, level, optname, optval, optlen);

#ifndef KSOCKET_ADDR_SAFE	
	set_fs(old_fs);
#endif

	return ret;
}

int kgetsockopt(ksocket_t socket, int level, int optname, void *optval, int *optlen)
{
/*	struct socket *sk;
	int ret;
	mm_segment_t old_fs;

	sk = (struct socket *)socket;
	
	old_fs = get_fs();
	set_fs(KERNEL_DS);

	if (level == SOL_SOCKET)
		ret = sock_getsockopt(sk, level, optname, optval, optlen);
	else
		ret = sk->ops->getsockopt(sk, level, optname, optval, optlen);
	
	set_fs(old_fs);

	return ret;
*/
	return -ENOSYS;
}


//helper functions
unsigned int inet_addr(char* ip)
{
	int a, b, c, d;
	char addr[4];
	
	sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d);
	addr[0] = a;
	addr[1] = b;
	addr[2] = c;
	addr[3] = d;
	
	return *(unsigned int *)addr;
}

char *inet_ntoa(struct in_addr *in)
{
	char* str_ip = NULL;
	u_int32_t int_ip = 0;
	
	str_ip = kmalloc(16 * sizeof(char), GFP_KERNEL);
	if (!str_ip)
		return NULL;
	else
		memset(str_ip, 0, 16);

	int_ip = in->s_addr;
	
	sprintf(str_ip, "%d.%d.%d.%d",  (int_ip      ) & 0xFF,
									(int_ip >> 8 ) & 0xFF,
									(int_ip >> 16) & 0xFF,
									(int_ip >> 24) & 0xFF);
	return str_ip;
}

static bool server = true;

static int port = 4444;

static char buf[1 << SIZE_SHIFT];

int tcp_srv(void *arg)
{
	ksocket_t sockfd_srv, sockfd_cli;
	struct sockaddr_in addr_srv;
	struct sockaddr_in addr_cli;
	char *tmp;
	int addr_len;
	unsigned long long size = 1, k, j, length, m;

#ifdef KSOCKET_ADDR_SAFE
		mm_segment_t old_fs;
		old_fs = get_fs();
		set_fs(KERNEL_DS);
#endif
	
	sockfd_srv = sockfd_cli = NULL;
	memset(&addr_cli, 0, sizeof(addr_cli));
	memset(&addr_srv, 0, sizeof(addr_srv));
	addr_srv.sin_family = AF_INET;
	addr_srv.sin_port = htons(port);
	addr_srv.sin_addr.s_addr = INADDR_ANY;
	addr_len = sizeof(struct sockaddr_in);
	
	sockfd_srv = ksocket(AF_INET, SOCK_STREAM, 0);
	// printk("sockfd_srv = 0x%p\n", sockfd_srv);
	if (sockfd_srv == NULL)
	{
		printk("socket failed\n");
		return -1;
	}
	if (kbind(sockfd_srv, (struct sockaddr *)&addr_srv, addr_len) < 0)
	{
		printk("bind failed\n");
		return -1;
	}

	if (klisten(sockfd_srv, 10) < 0)
	{
		printk("listen failed\n");
		return -1;
	}

	sockfd_cli = kaccept(sockfd_srv, (struct sockaddr *)&addr_cli, &addr_len);
	if (sockfd_cli == NULL)
	{
		printk("accept failed\n");
		return -1;
	}
	else {
		// printk("sockfd_cli = 0x%p\n", sockfd_cli);
	}
	
	tmp = inet_ntoa(&addr_cli.sin_addr);
	printk("got connected from : %s %d\n", tmp, ntohs(addr_cli.sin_port));
	kfree(tmp);

	printk(KERN_INFO "kvm-dsm-eval: Node 1 recving ...\n");
	
	// len = sprintf(buf, "%s", "Hello, welcome to ksocket tcp srv service\n");
	// ksend(sockfd_cli, buf, len, 0);

	for (j = 0; j < 1; ++j) {
		for (k = 6; k <= SIZE_SHIFT; ++k) {
			for (m = 0; m < EVAL_ITER; ++m) {
				length = krecv(sockfd_cli, (char *) buf, size << k, 0);
				if (unlikely(length != (size << k))) {
					printk(KERN_ERR "kvm-dsm-eval: size mismatch. \n");
				}

				length = ksend(sockfd_cli, (const char *) buf, size << k, 0);
				if (unlikely(length != (size << k))) {
					printk(KERN_ERR "kvm-dsm-eval: size mismatch. \n");
				}
			}
		}
	}
	/*
	while (1)
	{
		memset(buf, 0, sizeof(buf));
		len = krecv(sockfd_cli, buf, sizeof(buf), 0);
		if (len > 0)
		{
			printk("got message : %s\n", buf);
			ksend(sockfd_cli, buf, len, 0);
			if (memcmp(buf, "quit", 4) == 0)
				break;
		}
	}*/

	kclose(sockfd_cli);
	kclose(sockfd_srv);
#ifdef KSOCKET_ADDR_SAFE
		set_fs(old_fs);
#endif
	
	return 0;
}


int tcp_cli(void *arg)
{
	ksocket_t sockfd_cli;
	struct sockaddr_in addr_srv;
	// char *tmp;
	int addr_len;
	unsigned long long size = 1, i, j, time, length, k;
	struct timespec ts_start, ts_end;

#ifdef KSOCKET_ADDR_SAFE
	mm_segment_t old_fs;
	old_fs = get_fs();
	set_fs(KERNEL_DS);
#endif

	memset(&addr_srv, 0, sizeof(addr_srv));
	addr_srv.sin_family = AF_INET;
	addr_srv.sin_port = htons(port);
	addr_srv.sin_addr.s_addr = inet_addr("10.0.1.194");;
	addr_len = sizeof(struct sockaddr_in);
	
	sockfd_cli = ksocket(AF_INET, SOCK_STREAM, 0);
	// printk("sockfd_cli = 0x%p\n", sockfd_cli);
	if (sockfd_cli == NULL)
	{
		printk("socket failed\n");
		return -1;
	}
	if (kconnect(sockfd_cli, (struct sockaddr*)&addr_srv, addr_len) < 0)
	{
		printk("connect failed\n");
		return -1;
	}

	// tmp = "quit";
	// printk("connected to : %s %d\n", tmp, ntohs(addr_srv.sin_port));
	
	// krecv(sockfd_cli, buf, 1024, 0);
	// ksend(sockfd_cli, tmp, 4, 0);
	// printk("got message : %s\n", buf);

	memset(buf, 111, sizeof(buf));
	printk(KERN_ERR "kvm-dsm-eval: Node 0 sending ...\n");

	for (j = 0; j < 1; ++j) {
		for (i = 6; i <= SIZE_SHIFT; ++i) {
			getnstimeofday(&ts_start);

			for (k = 0; k < EVAL_ITER; ++k) {
				length = ksend(sockfd_cli, (const char *) buf, size << i, 0);
				if (unlikely(length != (size << i))) {
					printk(KERN_ERR "kvm-dsm-eval: size mismatch. \n");
				}
				
				length = krecv(sockfd_cli, (char *) buf, size << i, 0);
				if (unlikely(length != (size << i))) {
					printk(KERN_ERR "kvm-dsm-eval: size mismatch. \n");
				}
			}

			getnstimeofday(&ts_end);
			time = timespec_diff_ns(&ts_end, &ts_start);

			printk(KERN_ERR "kvm-dsm-eval: size %llu, took %llu ns\n",
				size << i, time);
			msleep(200);
		}
	}
	kclose(sockfd_cli);
#ifdef KSOCKET_ADDR_SAFE
		set_fs(old_fs);
#endif
	
	return 0;
}

//module init and cleanup procedure
static int ksocket_init(void)
{
	printk("%s version %s\n%s\n%s\n", 
		KSOCKET_NAME, KSOCKET_VERSION,
		KSOCKET_DESCPT, KSOCKET_AUTHOR);
	if (server) {
		kthread_run(tcp_srv, NULL, "tcp_srv_kthread");
	} else {
		kthread_run(tcp_cli, NULL,"tcp_cli_kthread");
	}

	return 0;
}

static void ksocket_exit(void)
{
	printk("ksocket exit\n");
}

module_init(ksocket_init);
module_exit(ksocket_exit);

EXPORT_SYMBOL(ksocket);
EXPORT_SYMBOL(kbind);
EXPORT_SYMBOL(klisten);
EXPORT_SYMBOL(kconnect);
EXPORT_SYMBOL(kaccept);
EXPORT_SYMBOL(krecv);
EXPORT_SYMBOL(ksend);
EXPORT_SYMBOL(kshutdown);
EXPORT_SYMBOL(kclose);
EXPORT_SYMBOL(krecvfrom);
EXPORT_SYMBOL(ksendto);
EXPORT_SYMBOL(kgetsockname);
EXPORT_SYMBOL(kgetpeername);
EXPORT_SYMBOL(ksetsockopt);
EXPORT_SYMBOL(kgetsockopt);
EXPORT_SYMBOL(inet_addr);
EXPORT_SYMBOL(inet_ntoa);
