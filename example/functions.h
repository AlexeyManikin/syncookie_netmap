/*
 * extract the extremes from a range of ipv4 addresses.
 * addr_lo[-addr_hi][:port_lo[-port_hi]]
 */
static void
extract_ip_data(struct ip_data *r)
{
	char *ap, *buf_name;
	struct in_addr a;
	int i = 0, x, lineCount = 0;
	char line[MAX_IP_RANGE_STRLEN];

	if(strstr(r->name, ".iplist") != NULL) {
		if (verbose)
			D("extract IP iplist from file %s", r->name);

		FILE *file = fopen(r->name, "r" ); 
		if (file == NULL){
			printf("Cannot open file %s", r->name);
			exit(1);
		}

		while (fgets(line, sizeof(line), file) != NULL) {
			lineCount++;
		}
		rewind(file);
		r->ranges = malloc(sizeof(line) * lineCount);

		while (i < lineCount && fgets(line, sizeof(line), file) != NULL){
			// Delete \n and \t symbols
			for(ap = line; *ap != '\0'; ++ap){
				switch(*ap){
					case '\n': *ap = '\0'; break;
					case '\t': *ap = '\0'; break;
				}
			}
			inet_aton(line, &a);
			r->ranges[i].start = ntohl(a.s_addr);
			r->ranges[i].end = 0;
			i++;
		}
		fclose(file);
		r->count = lineCount;
		r->type = IP_LIST_FILE;
		// for(i = 0; i < 10; i++ ) {
		// 	printf("Line #%d: start_ip %ld end_ip %ld\n", i, (long int)r->ranges[i].start, (long int)r->ranges[i].end);
		// }
		D("iplist file %s (%d ip addresses)", r->name, r->count);
	} else if(strstr(r->name, ".geoip") != NULL) {
		if (verbose)
			D("extract IP ranges from file %s", r->name);

		FILE *file = fopen(r->name, "r" ); 
		if (file == NULL){
			printf("Cannot open file %s", r->name);
			exit(1);
		}

		while (fgets(line, sizeof(line), file) != NULL) {
			lineCount++;
		}
		rewind(file);
		r->ranges = malloc(sizeof(line) * lineCount);

		while (i < lineCount && fgets(line, sizeof(line), file) != NULL){
			// Delete \n and \t symbols
			for(ap = line; *ap != '\0'; ++ap){
				switch(*ap){
					case '\n': *ap = '\0'; break;
					case '\t': *ap = '\0'; break;
				}
			}
			x = 0;
			for (ap = strtok(line,"-"); ap != NULL; ap = strtok(NULL, "-"), x++)
			{
				inet_aton(ap, &a);
				if(x == 0) {
					r->ranges[i].start = ntohl(a.s_addr);
				}
				if(x == 1) {
					r->ranges[i].end = ntohl(a.s_addr);
				}
			}
			i++;
		}
		fclose(file);
		r->count = lineCount;
		r->type = IP_GEOIP_FILE;
		// for(i = 0; i < r->count; i++ ) {
		// 	printf("Line #%d: start_ip %ld end_ip %ld\n", i, (long int)r->ranges[i].start, (long int)r->ranges[i].end);
		// }
		D("geoip file %s (%d ip ranges)", r->name, r->count);
	} else if(strchr(r->name, ',') != NULL) {
		if (verbose)
			D("extract IP list from %s", r->name);
		D("ip list is %s", r->name);
		// We count the number of occurrences
		buf_name = malloc(strlen(r->name));
		strcpy(buf_name, r->name);
		for (ap = strtok(buf_name,","); ap != NULL; ap = strtok(NULL, ","))
		{
			lineCount++;
		}
		// Free buf memory
		free(buf_name);
		// Allocated memory in ranges
		r->ranges = malloc(sizeof(*r->ranges) * lineCount);
		// Fill ranges
		for (ap = strtok(r->name,","); ap != NULL; ap = strtok(NULL, ","), i++)
		{
			inet_aton(ap, &a);
			r->ranges[i].start = ntohl(a.s_addr);
			r->ranges[i].end = 0;
		}
		r->count = i;
		r->type = IP_LIST;
	} else {
		if (verbose)
			D("extract IP range from %s", r->name);
		r->ranges = malloc(sizeof(*r->ranges));
		r->ranges->start = r->ranges->end = 0;
		/* the first - splits start/end of range */
		ap = index(r->name, '-');	/* do we have ports ? */
		if (ap) {
			*ap++ = '\0';
		}
		inet_aton(r->name, &a);
		r->ranges->start = r->ranges->end = ntohl(a.s_addr);
		if (ap) {

			if (*ap) {
				inet_aton(ap, &a);
				r->ranges->end = ntohl(a.s_addr);
			}
		}

		if (r->ranges->start > r->ranges->end) {
			uint32_t tmp = r->ranges->start;
			r->ranges->start = r->ranges->end;
			r->ranges->end = tmp;
		}
		{
			struct in_addr a;
			char buf1[16]; // one ip address

			a.s_addr = htonl(r->ranges->end);
			strncpy(buf1, inet_ntoa(a), sizeof(buf1));
			a.s_addr = htonl(r->ranges->start);

			D("ip range is %s to %s", inet_ntoa(a), buf1);
		}
		r->type = IP_RANGE;
	}
}

static void
extract_mac_range(struct mac_range *r)
{
	if (verbose)
	    D("extract MAC range from %s", r->name);
	bcopy(ether_aton(r->name), &r->start, 6);
	bcopy(ether_aton(r->name), &r->end, 6);
#if 0
	bcopy(targ->src_mac, eh->ether_shost, 6);
	p = index(targ->g->src_mac, '-');
	if (p)
		targ->src_mac_range = atoi(p+1);

	bcopy(ether_aton(targ->g->dst_mac), targ->dst_mac, 6);
	bcopy(targ->dst_mac, eh->ether_dhost, 6);
	p = index(targ->g->dst_mac, '-');
	if (p)
		targ->dst_mac_range = atoi(p+1);
#endif
	if (verbose)
		D("%s starts at %s", r->name, ether_ntoa(&r->start));
}

/* control-C handler */
static void
sigint_h(int sig)
{
	int i;

	(void)sig;	/* UNUSED */
	D("received control-C on thread %p", (void *)pthread_self());
	for (i = 0; i < global_nthreads; i++) {
		targs[i].cancel = 1;
	}
	signal(SIGINT, SIG_DFL);
}

/* sysctl wrapper to return the number of active CPUs */
static int
system_ncpus(void)
{
	int ncpus;
	ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	return (ncpus);
}

/*
 * parse the vale configuration in conf and put it in nmr.
 * Return the flag set if necessary.
 * The configuration may consist of 0 to 4 numbers separated
 * by commas: #tx-slots,#rx-slots,#tx-rings,#rx-rings.
 * Missing numbers or zeroes stand for default values.
 * As an additional convenience, if exactly one number
 * is specified, then this is assigned to both #tx-slots and #rx-slots.
 * If there is no 4th number, then the 3rd is assigned to both #tx-rings
 * and #rx-rings.
 */
int
parse_nmr_config(const char* conf, struct nmreq *nmr)
{
	char *w, *tok;
	int i, v;

	nmr->nr_tx_rings = nmr->nr_rx_rings = 0;
	nmr->nr_tx_slots = nmr->nr_rx_slots = 0;
	if (conf == NULL || ! *conf)
		return 0;
	w = strdup(conf);
	for (i = 0, tok = strtok(w, ","); tok; i++, tok = strtok(NULL, ",")) {
		v = atoi(tok);
		switch (i) {
		case 0:
			nmr->nr_tx_slots = nmr->nr_rx_slots = v;
			break;
		case 1:
			nmr->nr_rx_slots = v;
			break;
		case 2:
			nmr->nr_tx_rings = nmr->nr_rx_rings = v;
			break;
		case 3:
			nmr->nr_rx_rings = v;
			break;
		default:
			D("ignored config: %s", tok);
			break;
		}
	}
	D("txr %d txd %d rxr %d rxd %d",
			nmr->nr_tx_rings, nmr->nr_tx_slots,
			nmr->nr_rx_rings, nmr->nr_rx_slots);
	free(w);
	return (nmr->nr_tx_rings || nmr->nr_tx_slots ||
                        nmr->nr_rx_rings || nmr->nr_rx_slots) ?
		NM_OPEN_RING_CFG : 0;
}


/*
 * locate the src mac address for our interface, put it
 * into the user-supplied buffer. return 0 if ok, -1 on error.
 */
static int
source_hwaddr(const char *ifname, char *buf)
{
	struct ifaddrs *ifaphead, *ifap;
	int l = sizeof(ifap->ifa_name);

	if (getifaddrs(&ifaphead) != 0) {
		D("getifaddrs %s failed", ifname);
		return (-1);
	}

	for (ifap = ifaphead; ifap; ifap = ifap->ifa_next) {
		struct sockaddr_dl *sdl =
			(struct sockaddr_dl *)ifap->ifa_addr;
		uint8_t *mac;

		if (!sdl || sdl->sdl_family != AF_LINK)
			continue;
		if (strncmp(ifap->ifa_name, ifname, l) != 0)
			continue;
		mac = (uint8_t *)LLADDR(sdl);
		sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
			mac[0], mac[1], mac[2],
			mac[3], mac[4], mac[5]);
		if (verbose)
			D("source hwaddr %s", buf);
		break;
	}
	freeifaddrs(ifaphead);
	return ifap ? 0 : 1;
}




/* Compute the checksum of the given ip header. */
static uint16_t
checksum(const void *data, uint16_t len, uint32_t sum)
{
        const uint8_t *addr = data;
	uint32_t i;

        /* Checksum all the pairs of bytes first... */
        for (i = 0; i < (len & ~1U); i += 2) {
                sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
                if (sum > 0xFFFF)
                        sum -= 0xFFFF;
        }
	/*
	 * If there's a single byte left over, checksum it, too.
	 * Network byte order is big-endian, so the remaining byte is
	 * the high byte.
	 */
	if (i < len) {
		sum += addr[i] << 8;
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	return sum;
}

static u_int16_t
wrapsum(u_int32_t sum)
{
	sum = ~sum & 0xFFFF;
	return (htons(sum));
}

/*
* Calculate checksum TCP packet
*/
/*  * sum_w()  * 
 * Do the one's complement sum thing over a range of words 
 * Ideally, this should get replaced by an assembly version. 
 */
static uint32_t sum_w(uint16_t *buf, int nwords) {
        /*
        * Our algorithm is simple, using a 32-bit accumulator (sum),
        * we add sequential 16-bit words to it, and at the end, fold back 
        * all the carry bits from the top 16 bits into the lower 16 bits. 
        */
        register uint32_t sum = 0;
        while (nwords--) {
                sum += (uint16_t) ntohs(*buf++);
        }
        return (sum);
}

int tcp_csum(struct ip *ip, struct tcphdr * const tcp) {// 
	//struct tcphdr *const tcp = (struct tcphdr *) ((long *) ip + ip->ip_hl);
        uint32_t sum;
        int tcp_len;
        /* Calculate total length of the TCP segment in bytes */
        tcp_len = (uint16_t) ntohs(ip->ip_len) - (ip->ip_hl * 4);
        // DEBUG
        //printf("TCP segment len: %d bytes\n", tcp_len);
        //printf("IP header len: %02x (%d)\n", (ip->ip_hl * 4), (ip->ip_hl * 4));
        //printf("IP total len: %02x (%d)\n", ntohs(ip->ip_len), ntohs(ip->ip_len));
        
        /* add source and destination ip to sum */
        sum = sum_w((uint16_t*)&ip->ip_src, 4);
	// DEBUG
	//printf("Src addr: %s\n", inet_ntoa(ip->ip_src));
	//printf("Dst addr: %s\n", inet_ntoa(ip->ip_dst));

        sum += (uint16_t) IPPROTO_TCP;
        sum += (uint16_t) tcp_len;

        /* Sum up tcp part */
        sum += sum_w((uint16_t*) tcp, tcp_len >> 1);
	if (tcp_len & 1)
                sum += (uint16_t)(((u_char *) tcp)[tcp_len - 1] << 8);

        /* Flip it & stick it */
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        sum = ~sum;
	// DEBUG
        //printf("TCP checksum: %02x (%d)\n", ntohs(sum), sum);

        return htons(sum);
}


/* Check the payload of the packet for errors (use it for debug).
 * Look for consecutive ascii representations of the size of the packet.
 */
static void
dump_payload(const char *_p, int len, struct netmap_ring *ring, int cur)
{
	char buf[128];
	int i, j, i0;
	const unsigned char *p = (const unsigned char *)_p;

	/* get the length in ASCII of the length of the packet. */

	if (ring != NULL)
		printf("ring %p cur %5d [buf %6d flags 0x%04x len %5d]\n",
			ring, cur, ring->slot[cur].buf_idx,
			ring->slot[cur].flags, len);
	/* hexdump routine */
	for (i = 0; i < len; ) {
		memset(buf, sizeof(buf), ' ');
		sprintf(buf, "%5d: ", i);
		i0 = i;
		for (j=0; j < 16 && i < len; i++, j++)
			sprintf(buf+7+j*3, "%02x ", (uint8_t)(p[i]));
		i = i0;
		for (j=0; j < 16 && i < len; i++, j++)
			sprintf(buf+7+j + 48, "%c",
				isprint(p[i]) ? p[i] : '.');
		printf("%s\n", buf);
	}
}



/*
 * create and enqueue a batch of packets on a ring.
 * On the last one set NS_REPORT to tell the driver to generate
 * an interrupt when done.
 */
static int
send_packets(struct netmap_ring *ring, struct pkt *pkt, u_int count, int options,
		u_int nfrags, int size)
{
	u_int n, sent, cur = ring->cur;
	u_int fcnt;

	n = nm_ring_space(ring);
	if (n < count)
		count = n;
	if (count < nfrags) {
		D("truncating packet, no room for frags %d %d",
				count, nfrags);
	}

	for (fcnt = nfrags, sent = 0; sent < count; sent++) {
		struct netmap_slot *slot = &ring->slot[cur];
		char *p = NETMAP_BUF(ring, slot->buf_idx);

		//D("fcnt %d nfrags %d sent %d count %d", fcnt, nfrags, sent, count);
		nm_pkt_copy(pkt, p, size);
		slot->len = size;
		slot->flags = 0;

		if (options & OPT_DUMP)
			dump_payload(p, size, ring, cur);
		if (--fcnt > 0)
			slot->flags |= NS_MOREFRAG;
		else
			fcnt = nfrags;
		if (sent == count - 1) {
			slot->flags &= ~NS_MOREFRAG;
			slot->flags |= NS_REPORT;
		}
		cur = nm_ring_next(ring, cur);
	}
	ring->head = ring->cur = cur;

	return (sent);
}


/*
 * Send a packet, and wait for a response.
 * The payload (after UDP header, ofs 42) has a 4-byte sequence
 * followed by a struct timeval (or bintime?)
 */
#define	PAY_OFS	42	/* where in the pkt... */

static __inline int
timespec_ge(const struct timespec *a, const struct timespec *b)
{

	if (a->tv_sec > b->tv_sec)
		return (1);
	if (a->tv_sec < b->tv_sec)
		return (0);
	if (a->tv_nsec >= b->tv_nsec)
		return (1);
	return (0);
}

static __inline struct timespec
timeval2spec(const struct timeval *a)
{
	struct timespec ts = {
		.tv_sec = a->tv_sec,
		.tv_nsec = a->tv_usec * 1000
	};
	return ts;
}

static __inline struct timeval
timespec2val(const struct timespec *a)
{
	struct timeval tv = {
		.tv_sec = a->tv_sec,
		.tv_usec = a->tv_nsec / 1000
	};
	return tv;
}


static __inline struct timespec
timespec_add(struct timespec a, struct timespec b)
{
	struct timespec ret = { a.tv_sec + b.tv_sec, a.tv_nsec + b.tv_nsec };
	if (ret.tv_nsec >= 1000000000) {
		ret.tv_sec++;
		ret.tv_nsec -= 1000000000;
	}
	return ret;
}

static __inline struct timespec
timespec_sub(struct timespec a, struct timespec b)
{
	struct timespec ret = { a.tv_sec - b.tv_sec, a.tv_nsec - b.tv_nsec };
	if (ret.tv_nsec < 0) {
		ret.tv_sec--;
		ret.tv_nsec += 1000000000;
	}
	return ret;
}


/*
 * wait until ts, either busy or sleeping if more than 1ms.
 * Return wakeup time.
 */
static struct timespec
wait_time(struct timespec ts)
{
	for (;;) {
		struct timespec w, cur;
		clock_gettime(CLOCK_REALTIME_PRECISE, &cur);
		w = timespec_sub(ts, cur);
		if (w.tv_sec < 0)
			return cur;
		else if (w.tv_sec > 0 || w.tv_nsec > 1000000)
			poll(NULL, 0, 1);
	}
}


static void *
sender_body(void *data)
{
	struct targ *targ = (struct targ *) data;
	struct pollfd pfd = { .fd = targ->fd, .events = POLLOUT };
	struct netmap_if *nifp;
	struct netmap_ring *txring = NULL;
	int i, n = targ->g->npackets / targ->g->nthreads;
	int64_t sent = 0;
	uint64_t event = 0;
	int options = targ->g->options | OPT_COPY;
	struct timespec nexttime = { 0, 0}; // XXX silence compiler
	int rate_limit = targ->g->tx_rate;
	struct pkt *pkt = &targ->pkt;
	int size = targ->pkt_size;
	
	D("start, fd %d main_fd %d", targ->fd, targ->g->main_fd);
	if (setaffinity(targ->thread, targ->affinity))
		goto quit;

	/* main loop.*/
	clock_gettime(CLOCK_REALTIME_PRECISE, &targ->tic);
	if (rate_limit) {
		targ->tic = timespec_add(targ->tic, (struct timespec){2,0});
		targ->tic.tv_nsec = 0;
		wait_time(targ->tic);
		nexttime = targ->tic;
	}

	int tosend = 0;
	int frags = targ->g->frags;

	nifp = targ->nmd->nifp;
	while (!targ->cancel && (n == 0 || sent < n)) {

		if (rate_limit && tosend <= 0) {
			tosend = targ->g->burst;
			nexttime = timespec_add(nexttime, targ->g->tx_period);
			wait_time(nexttime);
		}

		/*
		 * wait for available room in the send queue(s)
		 */
		if (poll(&pfd, 1, 2000) <= 0) {
			if (targ->cancel)
				break;
			D("poll error/timeout on queue %d: %s", targ->me,
				strerror(errno));
			// goto quit;
		}
		if (pfd.revents & POLLERR) {
			D("poll error on %d ring %d-%d", pfd.fd,
				targ->nmd->first_tx_ring, targ->nmd->last_tx_ring);
			goto quit;
		}
		/*
		 * scan our queues and send on those with room
		 */
		if (options & OPT_COPY && sent > 100000 && !(targ->g->options & OPT_COPY) ) {
			options &= ~OPT_COPY;
		}
		for (i = targ->nmd->first_tx_ring; i <= targ->nmd->last_tx_ring; i++) {
			size = targ->pkt_size;

			int m, limit = rate_limit ?  tosend : targ->g->burst;
			if (n > 0 && n - sent < limit)
				limit = n - sent;
			txring = NETMAP_TXRING(nifp, i);
			if (nm_ring_empty(txring))
				continue;
			if (frags > 1)
				limit = ((limit + frags - 1) / frags) * frags;

			m = send_packets(txring, pkt, limit, options, frags, size);
			// Update packet
			change_packet(pkt, targ);
			//D("Thread #%d new packet size: %d", targ->me, targ->pkt_size);

			ND("limit %d tail %d frags %d m %d",
				limit, txring->tail, frags, m);
			sent += m;
			if (m > 0) //XXX-ste: can m be 0?
				event++;
			targ->ctr.pkts = sent;
			targ->ctr.bytes = sent*size;
			targ->ctr.events = event;
			if (rate_limit) {
				tosend -= m;
				if (tosend <= 0)
					break;
			}
		}
	}
	/* flush any remaining packets */
	D("flush tail %d head %d on thread %p",
		txring->tail, txring->head,
		(void *)pthread_self());
	ioctl(pfd.fd, NIOCTXSYNC, NULL);

	/* final part: wait all the TX queues to be empty. */
	for (i = targ->nmd->first_tx_ring; i <= targ->nmd->last_tx_ring; i++) {
		txring = NETMAP_TXRING(nifp, i);
		while (nm_tx_pending(txring)) {
			RD(5, "pending tx tail %d head %d on ring %d",
				txring->tail, txring->head, i);
			ioctl(pfd.fd, NIOCTXSYNC, NULL);
			usleep(1); /* wait 1 tick */
		}
	}

	clock_gettime(CLOCK_REALTIME_PRECISE, &targ->toc);
	targ->completed = 1;
	targ->ctr.pkts = sent;
	targ->ctr.bytes = sent*size;
	targ->ctr.events = event;
quit:
	/* reset the ``used`` flag. */
	targ->used = 0;

	return (NULL);
}


/* very crude code to print a number in normalized form.
 * Caller has to make sure that the buffer is large enough.
 */
static const char *
norm2(char *buf, double val, char *fmt)
{
	char *units[] = { "", "K", "M", "G", "T" };
	u_int i;

	for (i = 0; val >=1000 && i < sizeof(units)/sizeof(char *) - 1; i++)
		val /= 1000;
	sprintf(buf, fmt, val, units[i]);
	return buf;
}

static const char *
norm(char *buf, double val)
{
	return norm2(buf, val, "%.3f %s");
}

static void
tx_output(struct my_ctrs *cur, double delta, const char *msg)
{
	double bw, raw_bw, pps, abs;
	char b1[40], b2[80], b3[80];
	int size;

	if (cur->pkts == 0) {
		printf("%s nothing.\n", msg);
		return;
	}

	size = (int)(cur->bytes / cur->pkts);

	printf("%s %llu packets %llu bytes %llu events %d bytes each in %.2f seconds.\n",
		msg,
		(unsigned long long)cur->pkts,
		(unsigned long long)cur->bytes,
		(unsigned long long)cur->events, size, delta);
	if (delta == 0)
		delta = 1e-6;
	if (size < 60)		/* correct for min packet size */
		size = 60;
	pps = cur->pkts / delta;
	bw = (8.0 * cur->bytes) / delta;
	/* raw packets have4 bytes crc + 20 bytes framing */
	raw_bw = (8.0 * (cur->pkts * 24 + cur->bytes)) / delta;
	abs = cur->pkts / (double)(cur->events);

	printf("Speed: %spps Bandwidth: %sbps (raw %sbps). Average batch: %.2f pkts\n",
		norm(b1, pps), norm(b2, bw), norm(b3, raw_bw), abs);
}

static void
start_threads(struct glob_arg *g)
{
	int i;

	targs = calloc(g->nthreads, sizeof(*targs));
	/*
	 * Now create the desired number of threads, each one
	 * using a single descriptor.
 	 */
	for (i = 0; i < g->nthreads; i++) {
		struct targ *t = &targs[i];

		bzero(t, sizeof(*t));
		t->fd = -1; /* default, with pcap */
		t->g = g;
		t->tic_cng_payload=0;
		t->pkt_size = g->pkt_size;

		if (g->dev_type == DEV_NETMAP) {
			struct nm_desc nmd = *g->nmd; /* copy, we overwrite ringid */
			uint64_t nmd_flags = 0;
			nmd.self = &nmd;

			if (i > 0) {
				/* the first thread uses the fd opened by the main
			 	* thread, the other threads re-open /dev/netmap
			 	*/
				if (g->nthreads > 1) {
					nmd.req.nr_flags =
						g->nmd->req.nr_flags & ~NR_REG_MASK;
					nmd.req.nr_flags |= NR_REG_ONE_NIC;
					nmd.req.nr_ringid = i;
				}

				/* register interface. Override ifname and ringid etc. */
				t->nmd = nm_open(t->g->ifname, NULL, nmd_flags |
					NM_OPEN_IFNAME | NM_OPEN_NO_MMAP, &nmd);
				if (t->nmd == NULL) {
					D("Unable to open %s: %s",
						t->g->ifname, strerror(errno));
					continue;
				}
			} else {
				t->nmd = g->nmd;
			}
			t->fd = t->nmd->fd;

		} else {
			targs[i].fd = g->main_fd;
	    	}
		t->used = 1;
		t->me = i;
		if (g->affinity >= 0) {
			t->affinity = (g->affinity + i) % g->system_cpus;
		} else {
			t->affinity = -1;
		}
		/* default, init packets */
		initialize_packet(t);

		if (pthread_create(&t->thread, NULL, g->td_body, t) == -1) {
			D("Unable to create thread %d: %s", i, strerror(errno));
			t->used = 0;
		}
	}
}

static void
main_thread(struct glob_arg *g)
{
	int i;

	struct my_ctrs prev, cur;
	double delta_t;
	struct timeval tic, toc;

	prev.pkts = prev.bytes = prev.events = 0;
	gettimeofday(&prev.t, NULL);
	for (;;) {
		char b1[40], b2[40], b3[40];
		struct timeval delta;
		uint64_t pps, usec;
		struct my_ctrs x;
		double abs;
		int done = 0;

		delta.tv_sec = g->report_interval/1000;
		delta.tv_usec = (g->report_interval%1000)*1000;
		select(0, NULL, NULL, NULL, &delta);
		cur.pkts = cur.bytes = cur.events = 0;
		gettimeofday(&cur.t, NULL);
		timersub(&cur.t, &prev.t, &delta);
		usec = delta.tv_sec* 1000000 + delta.tv_usec;
		if (usec < 10000) /* too short to be meaningful */
			continue;
		/* accumulate counts for all threads */
		for (i = 0; i < g->nthreads; i++) {
			cur.pkts += targs[i].ctr.pkts;
			cur.bytes += targs[i].ctr.bytes;
			cur.events += targs[i].ctr.events;
			if (targs[i].used == 0)
				done++;
		}
		x.pkts = cur.pkts - prev.pkts;
		x.bytes = cur.bytes - prev.bytes;
		x.events = cur.events - prev.events;
		pps = (x.pkts*1000000 + usec/2) / usec;
		abs = (x.events > 0) ? (x.pkts / (double) x.events) : 0;

		D("%spps (%spkts %sbps in %llu usec) %.2f avg_batch",
			norm(b1,pps),
			norm(b2, (double)x.pkts),
			norm(b3, (double)x.bytes*8),
			(unsigned long long)usec,
			abs);
		prev = cur;
		if (done == g->nthreads)
			break;
	}

	timerclear(&tic);
	timerclear(&toc);
	cur.pkts = cur.bytes = cur.events = 0;
	/* final round */
	for (i = 0; i < g->nthreads; i++) {
		struct timespec t_tic, t_toc;
		/*
		 * Join active threads, unregister interfaces and close
		 * file descriptors.
		 */
		if (targs[i].used)
			pthread_join(targs[i].thread, NULL); /* blocking */
		close(targs[i].fd);

		if (targs[i].completed == 0)
			D("ouch, thread %d exited with error", i);

		/*
		 * Collect threads output and extract information about
		 * how long it took to send all the packets.
		 */
		cur.pkts += targs[i].ctr.pkts;
		cur.bytes += targs[i].ctr.bytes;
		cur.events += targs[i].ctr.events;
		/* collect the largest start (tic) and end (toc) times,
		 * XXX maybe we should do the earliest tic, or do a weighted
		 * average ?
		 */
		t_tic = timeval2spec(&tic);
		t_toc = timeval2spec(&toc);
		if (!timerisset(&tic) || timespec_ge(&targs[i].tic, &t_tic))
			tic = timespec2val(&targs[i].tic);
		if (!timerisset(&toc) || timespec_ge(&targs[i].toc, &t_toc))
			toc = timespec2val(&targs[i].toc);
	}
	free(targs);

	/* print output. */
	timersub(&toc, &tic, &toc);
	delta_t = toc.tv_sec + 1e-6* toc.tv_usec;
	tx_output(&cur, delta_t, "Received");
	if (g->dev_type == DEV_NETMAP) {
		munmap(g->nmd->mem, g->nmd->req.nr_memsize);
		close(g->main_fd);
	}
}

static int
tap_alloc(char *dev)
{
	struct ifreq ifr;
	int fd, err;
	char *clonedev = TAP_CLONEDEV;

	(void)err;
	(void)dev;
	/* Arguments taken by the function:
	 *
	 * char *dev: the name of an interface (or '\0'). MUST have enough
	 *   space to hold the interface name if '\0' is passed
	 * int flags: interface flags (eg, IFF_TUN etc.)
	 */

	/* open the device */
	if( (fd = open(clonedev, O_RDWR)) < 0 ) {
		return fd;
	}
	D("%s open successful", clonedev);

	/* preparation of the struct ifr, of type "struct ifreq" */
	memset(&ifr, 0, sizeof(ifr));

#ifdef linux
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if (*dev) {
		/* if a device name was specified, put it in the structure; otherwise,
		* the kernel will try to allocate the "next" device of the
		* specified type */
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	/* try to create the device */
	if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
		D("failed to to a TUNSETIFF: %s", strerror(errno));
		close(fd);
		return err;
	}

	/* if the operation was successful, write back the name of the
	* interface to the variable "dev", so the caller can know
	* it. Note that the caller MUST reserve space in *dev (see calling
	* code below) */
	strcpy(dev, ifr.ifr_name);
	D("new name is %s", dev);
#endif /* linux */

        /* this is the special file descriptor that the caller will use to talk
         * with the virtual interface */
        return fd;
}

static void
initialize_iphdr(struct targ *t, struct ip *ip, int ipproto) {
	ip->ip_v = IPVERSION;
	ip->ip_hl = 5;
	ip->ip_id = 0;
	ip->ip_tos = IPTOS_LOWDELAY;
	ip->ip_len = ntohs(t->pkt_size - sizeof(struct ether_header));
	ip->ip_id = 0;
	ip->ip_off = htons(IP_DF); /* Don't fragment */
	ip->ip_ttl = IPDEFTTL;
	ip->ip_p = ipproto;
	ip->ip_dst.s_addr = htonl(t->g->dst_ip.ranges[0].start);
	ip->ip_src.s_addr = htonl(t->g->src_ip.ranges[0].start);
	ip->ip_sum = wrapsum(checksum(ip, sizeof(*ip), 0));
}

static void
initialize_ehhdr(struct targ *t, struct ether_header *eh) {
	bcopy(&t->g->src_mac.start, eh->ether_shost, 6);
	bcopy(&t->g->dst_mac.start, eh->ether_dhost, 6);
	eh->ether_type = htons(ETHERTYPE_IP);
}

static void
fill_rand_payload(struct pkt *pkt, int srnd, uint16_t paylen) {
	int i;
	srand(srnd);
	for( i = 0; i < paylen; ++i){
		pkt->body[i] = '0' + rand()%72;
	}
	pkt->body[i-1] = '\0';
}


static void
update_ip(struct targ *t, struct ip *ip) {
	int rand_rg, rand_ip;
	uint32_t a;

	/* XXX for now it doesn't handle non-random src, random dst */
	if (t->g->options & OPT_RANDOM_SRC) {
		ip->ip_src.s_addr = random();
	} else {
		if(t->g->src_ip.type == IP_GEOIP_FILE) {
			rand_rg = rand() % t->g->src_ip.count;
			rand_ip = rand() % ((t->g->src_ip.ranges[rand_rg].end - t->g->src_ip.ranges[rand_rg].start) + 1);
			ip->ip_src.s_addr = htonl(t->g->src_ip.ranges[rand_rg].start + rand_ip);
		} else if(t->g->src_ip.type == IP_LIST || t->g->src_ip.type == IP_LIST_FILE) {
			ip->ip_src.s_addr = htonl(t->g->src_ip.ranges[rand() % t->g->src_ip.count].start);
		} else {
			a = ntohl(ip->ip_src.s_addr);
			if (a < t->g->src_ip.ranges[0].end) { /* just inc, no wrap */
				ip->ip_src.s_addr = htonl(a + 1);
			} else {
				ip->ip_src.s_addr = htonl(t->g->src_ip.ranges[0].start);
			}
			
		}
	}
	if (t->g->options & OPT_RANDOM_DST) {
		ip->ip_dst.s_addr = random();
	} else {
		if(t->g->dst_ip.type == IP_GEOIP_FILE) {
			rand_rg = rand() % t->g->dst_ip.count;
			rand_ip = rand() % ((t->g->dst_ip.ranges[rand_rg].end - t->g->dst_ip.ranges[rand_rg].start) + 1);
			ip->ip_dst.s_addr = htonl(t->g->dst_ip.ranges[rand_rg].start + rand_ip);
		} else if(t->g->dst_ip.type == IP_LIST || t->g->dst_ip.type == IP_LIST_FILE) {
			ip->ip_dst.s_addr = htonl(t->g->dst_ip.ranges[rand() % t->g->dst_ip.count].start);
		} else {
			a = ntohl(ip->ip_dst.s_addr);
			if (a < t->g->dst_ip.ranges[0].end) { /* just inc, no wrap */
				ip->ip_dst.s_addr = htonl(a + 1);
			} else {
				ip->ip_dst.s_addr = htonl(t->g->dst_ip.ranges[0].start);
			}
		}
	}
}

static void
usage(void)
{
	fprintf(stderr,
		"Usage:\n"
		"%s arguments\n"
		"\t-i interface		interface name\n"
		"\t-n count		number of iterations (can be 0)\n"
		"\t-F frags		?\n"
		"\t-l pkt_size		max packet size in bytes excluding CRC\n"
		"\t-d dst_ip		single or range (ip-ip) or geoip file (*.geoip)\n"
		"\t-s src_ip		single or range (ip-ip) or geoip file (*.geoip)\n"
		"\t-D dst-mac\n"
		"\t-S src-mac\n"
		"\t-a cpu_id		use setaffinity\n"
		"\t-b burst size		testing, mostly\n"
		"\t-c cores		cores to use (default 1)\n"
		"\t-p threads		processes/threads to use\n"
		"\t-T report_ms		milliseconds between reports\n"
		"\t-R rate			in packets per second\n"
		"\t-X			dump payload\n"
		"\t-z			use random IPv4 src address\n"
		"\t-Z			use random IPv4 dst address\n"
		"\t-C config		custom nmr_config\n"
#if defined(PROTO_TCP) || defined(PROTO_UDP)
		"\t-u			use random port\n"
		"\t-U			use random dst port\n"
		"\t-k ports		use src ports\n"
		"\t-K ports		use dst ports\n"
		"\t-O			random payload data\n"
		"\t-A			random payload length (use only with -O)\n"
#endif /* end TCP or UDP */
#ifdef PROTO_TCP
		"\t-j			tcp flags (UAPRSF)\n"
#endif /* end PROTO_TCP */
#ifdef PROTO_ICMP
		"\t-N code icmp packet code [0-15]\n"
		"\t-L type icmp packet type\n"
#endif /* end ICMP */
		"\t-v			verbose mode\n"
		""
		"",
		cmd);

	exit(0);
}

static void
arg_parse(struct glob_arg *g, int arc, char **argv) {
	int ch, i;
	int res[MAX_SRC_PORTS];
	char *param;
	int devqueues = 1;	/* how many device queues */

	g->main_fd = -1;
	g->td_body = sender_body;
	g->report_interval = 1000;	/* report interval */
	g->affinity = -1;
	/* ip addresses can also be a range x.x.x.x-x.x.x.y */
	g->src_ip.name = "10.0.0.1";
	g->dst_ip.name = "10.1.0.1";
	g->dst_mac.name = "ff:ff:ff:ff:ff:ff";
	g->src_mac.name = NULL;
	g->pkt_size = 60;
	g->burst = 512;		// default
	g->nthreads = 1;
	g->cpus = 1;		// default
	g->tx_rate = 0;
	g->frags = 1;
	g->nmr_config = "";
	g->wait_link = 2;
	g->tcp_flags = "S";

	while ( (ch = getopt(arc, argv,
			"i:n:F:l:d:s:D:S:a:b:c:p:T:R:XzZC:uUk:K:OAj:N:L:vP:")) != -1) {
		switch(ch) {
			default:
				D("bad option %c %s", ch, optarg);
				usage();
				break;
			case 'i':	/* interface */
				/* a prefix of tap: netmap: or pcap: forces the mode.
				 * otherwise we guess
				 */
				D("interface is %s", optarg);
				if (strlen(optarg) > MAX_IFNAMELEN - 8) {
					D("ifname too long %s", optarg);
					break;
				}
				strcpy(g->ifname, optarg);
				if (!strcmp(optarg, "null")) {
					g->dev_type = DEV_NETMAP;
					g->dummy_send = 1;
				} else if (!strncmp(optarg, "tap:", 4)) {
					g->dev_type = DEV_TAP;
					strcpy(g->ifname, optarg + 4);
				} else if (!strncmp(optarg, "pcap:", 5)) {
					g->dev_type = DEV_PCAP;
					strcpy(g->ifname, optarg + 5);
				} else if (!strncmp(optarg, "netmap:", 7) ||
					   !strncmp(optarg, "vale", 4)) {
					g->dev_type = DEV_NETMAP;
				} else if (!strncmp(optarg, "tap", 3)) {
					g->dev_type = DEV_TAP;
				} else { /* prepend netmap: */
					g->dev_type = DEV_NETMAP;
					sprintf(g->ifname, "netmap:%s", optarg);
				}
				break;
			case 'n':
				g->npackets = atoi(optarg);
				break;
			case 'F':
				i = atoi(optarg);
				if (i < 1 || i > 63) {
					D("invalid frags %d [1..63], ignore", i);
					break;
				}
				g->frags = i;
				break;
			case 'l':	/* pkt_size */
				g->pkt_size = atoi(optarg);
				break;
			case 'd':
				g->dst_ip.name = optarg;
				break;
			case 's':
				g->src_ip.name = optarg;
				break;
			case 'D': /* destination mac */
				g->dst_mac.name = optarg;
				break;
			case 'S': /* source mac */
				g->src_mac.name = optarg;
				break;
			case 'a':       /* force affinity */
				g->affinity = atoi(optarg);
				break;
			case 'b':	/* burst */
				g->burst = atoi(optarg);
				break;
			case 'c':
				g->cpus = atoi(optarg);
				break;
			case 'p':
				g->nthreads = atoi(optarg);
				break;
			case 'T':	/* report interval */
				g->report_interval = atoi(optarg);
				break;
			case 'R':
				g->tx_rate = atoi(optarg);
				break;
			case 'X':
				g->options |= OPT_DUMP;
				break;
			case 'z':
				g->options |= OPT_RANDOM_SRC;
				break;
			case 'Z':
				g->options |= OPT_RANDOM_DST;
				break;
			case 'C':
				g->nmr_config = strdup(optarg);
				break;
			case 'u':
				g->options |= OPT_RANDOM_SRC_PORT;
				break;
			case 'U':
				g->options |= OPT_RANDOM_DST_PORT;
				break;
			case 'k':
				i = 0;
				D("Use source port list: %s", optarg);
				param = strtok (optarg, ",");
				while (param) {
					res[i] = atoi(param);
					param = strtok (NULL, ",");
					i++;
				}
				g->src_ports = malloc(i * sizeof(int));
				memcpy(g->src_ports, res, i * sizeof(int));
				g->count_src_ports = i;
				g->options |= OPT_SRC_PORT_LIST;
				break;
			case 'K':
				i = 0;
				D("Use destination port list: %s", optarg);
				param = strtok (optarg, ",");
				while (param) {
					res[i] = atoi(param);
					param = strtok (NULL, ",");
					i++;
				}
				g->dst_ports = malloc(i * sizeof(int));
				memcpy(g->dst_ports, res, i * sizeof(int));
				g->count_dst_ports = i;
				g->options |= OPT_DST_PORT_LIST;
				break;
#if defined(PROTO_TCP) || defined(PROTO_UDP)
			// TCP and UDP flags
			case 'O':
				g->options |= OPT_RANDOM_PAYLOAD;
				break;
			case 'A':
				g->options |= OPT_RANDOM_PAYLOAD_LEN;
				break;
#endif /* end TCP or UDP */
#ifdef PROTO_TCP
			// TCP specific flags
			case 'j':
				D("use TCP flags: %s", optarg);
				if (strlen(optarg) > strlen(TCP_FLAGS)) {
					D("TCP flags too long %s, use only flags: %s", optarg, TCP_FLAGS);
					break;
				} else {
					for(i = 0; optarg[i]; i++) {
						if(strchr(TCP_FLAGS, optarg[i]) == NULL) {
							D("Unsupported TCP flag %c", optarg[i]);
							optarg="S";
							break;
						}
					}
					g->tcp_flags=optarg;
				}	
				break;
#endif /* end PROTO_TCP */
#ifdef PROTO_ICMP
			// ICMP specific flags
			case 'N':
				g->icmp_code = atoi(optarg);
				break;
			case 'L':
				g->icmp_type = atoi(optarg);
				break;
#endif /* end PROTO_ICMP */
			case 'v':
				verbose++;
				break;
			case 'P':
				g->options |= OPT_PAYLOAD_FILE;
				g->payload_file = optarg;
				
		}
	}

	if (strlen(g->ifname) <=0 ) {
		D("missing ifname");
		usage();
	}

	if (g->options & OPT_PAYLOAD_FILE && (g->options & OPT_RANDOM_PAYLOAD || g->options & OPT_RANDOM_PAYLOAD_LEN)) {
		D("Flag -P do used not allow with flags -O or -A");
		usage();
	}

	if (g->options & OPT_PAYLOAD_FILE) { // if g->options & OPT_PAYLOAD_FILE
		FILE *file = fopen(g->payload_file, "rb" ); 
		if (file == NULL){
			printf("Cannot open file %s", g->payload_file);
			exit(1);
		}
		//Get file length
		fseek(file, 0, SEEK_END);
		g->payload_data_len = ftell(file);
		fseek(file, 0, SEEK_SET);
		// allocated memory
		g->payload_data = malloc(g->payload_data_len + 1);
		// read data from file
		i = fread(g->payload_data, g->payload_data_len, 1, file);
		fclose(file);

		D("load %ld bytes from payload file %s", g->payload_data_len, g->payload_file);

		// for(i = 0; i < g->payload_data_len; i++)
		// 	printf("%02X", g->payload_data[i]);
		// printf("\n");
	}

	g->system_cpus = i = system_ncpus();
	if (g->cpus < 0 || g->cpus > i) {
		D("%d cpus is too high, have only %d cpus", g->cpus, i);
		usage();
	}
	D("running on %d cpus (have %d)", g->cpus, i);
	if (g->cpus == 0)
		g->cpus = i;

	if (g->pkt_size < 16 || g->pkt_size > MAX_PKTSIZE) {
		D("bad pktsize %d [16..%d]\n", g->pkt_size, MAX_PKTSIZE);
		usage();
	}

	if (g->src_mac.name == NULL) {
		static char mybuf[20] = "00:00:00:00:00:00";
		/* retrieve source mac address. */
		if (source_hwaddr(g->ifname, mybuf) == -1) {
			D("Unable to retrieve source mac");
			// continue, fail later
		}
		g->src_mac.name = mybuf;
	}
	/* extract address ranges */
	D("Source ip addresses:");
	extract_ip_data(&g->src_ip);
	D("Destination ip addresses: ");
	extract_ip_data(&g->dst_ip);
				//load_ranges(optarg);
	extract_mac_range(&g->src_mac);
	extract_mac_range(&g->dst_mac);

#if defined(PROTO_TCP) || defined(PROTO_UDP)
	if (g->options & OPT_RANDOM_DST_PORT || g->options & OPT_DST_PORT_LIST) {}
	else {
		D("Missing destination port! Use key -U or key -K");
		usage();
	}

	if (g->options & OPT_RANDOM_SRC_PORT || g->options & OPT_SRC_PORT_LIST) {}
	else {
		D("Missing source port! Use key -u or key -k");
		usage();
	}
#endif /* end TCP or UDP */

	if (g->dev_type == DEV_TAP) {
		D("want to use tap %s", g->ifname);
		g->main_fd = tap_alloc(g->ifname);
		if (g->main_fd < 0) {
			D("cannot open tap %s", g->ifname);
			usage();
		}
#ifndef NO_PCAP
    } else if (g->dev_type == DEV_PCAP) {
		char pcap_errbuf[PCAP_ERRBUF_SIZE];

		pcap_errbuf[0] = '\0'; // init the buffer
		g->p = pcap_open_live(g->ifname, 256 /* XXX */, 1, 100, pcap_errbuf);
		if (g->p == NULL) {
			D("cannot open pcap on %s", g->ifname);
			usage();
		}
		g->main_fd = pcap_fileno(g->p);
		D("using pcap on %s fileno %d", g->ifname, g->main_fd);
#endif /* !NO_PCAP */
    } else if (g->dummy_send) { /* but DEV_NETMAP */
		D("using a dummy send routine");
    } else {
		struct nmreq base_nmd;

		bzero(&base_nmd, sizeof(base_nmd));

		parse_nmr_config(g->nmr_config, &base_nmd);

		/*
		 * Open the netmap device using nm_open().
		 *
		 * protocol stack and may cause a reset of the card,
		 * which in turn may take some time for the PHY to
		 * reconfigure. We do the open here to have time to reset.
		 */
		g->nmd = nm_open(g->ifname, &base_nmd, 0, NULL);
		if (g->nmd == NULL) {
			D("Unable to open %s: %s", g->ifname, strerror(errno));
			goto out;
		}
		if (g->nthreads > 1) {
			struct nm_desc saved_desc = *g->nmd;
			saved_desc.self = &saved_desc;
			saved_desc.mem = NULL;
			nm_close(g->nmd);
			saved_desc.req.nr_flags &= ~NR_REG_MASK;
			saved_desc.req.nr_flags |= NR_REG_ONE_NIC;
			saved_desc.req.nr_ringid = 0;
			g->nmd = nm_open(g->ifname, &base_nmd, NM_OPEN_IFNAME, &saved_desc);
			if (g->nmd == NULL) {
				D("Unable to open %s: %s", g->ifname, strerror(errno));
				goto out;
			}
		}
		g->main_fd = g->nmd->fd;
		D("mapped %dKB at %p", g->nmd->req.nr_memsize>>10, g->nmd->mem);

		/* get num of queues in tx or rx */
		if (g->td_body == sender_body)
			devqueues = g->nmd->req.nr_tx_rings;
		else
			devqueues = g->nmd->req.nr_rx_rings;

		/* validate provided nthreads. */
		if (g->nthreads < 1 || g->nthreads > devqueues) {
			D("bad nthreads %d, have %d queues", g->nthreads, devqueues);
			// continue, fail later
		}

		if (verbose) {
			struct netmap_if *nifp = g->nmd->nifp;
			struct nmreq *req = &g->nmd->req;

			D("nifp at offset %d, %d tx %d rx region %d",
			    req->nr_offset, req->nr_tx_rings, req->nr_rx_rings,
			    req->nr_arg2);
			for (i = 0; i <= req->nr_tx_rings; i++) {
				struct netmap_ring *ring = NETMAP_TXRING(nifp, i);
				D("   TX%d at 0x%lx slots %d", i,
				    (char *)ring - (char *)nifp, ring->num_slots);
			}
			for (i = 0; i <= req->nr_rx_rings; i++) {
				struct netmap_ring *ring = NETMAP_RXRING(nifp, i);
				D("   RX%d at 0x%p slots %d", i,
				    (void *)((char *)ring - (char *)nifp), ring->num_slots);
			}
		}

		/* Print some debug information. */
		fprintf(stdout,
			"%s %s: %d queues, %d threads and %d cpus.\n",
			(g->td_body == sender_body) ? "Sending on" : "Receiving from",
			g->ifname,
			devqueues,
			g->nthreads,
			g->cpus);
		if (g->td_body == sender_body) {
			fprintf(stdout, "proto TCP %s -> %s (%s -> %s)\n",
				g->src_ip.name, g->dst_ip.name,
				g->src_mac.name, g->dst_mac.name);
		}

out:
		/* Exit if something went wrong-> */
		if (g->main_fd < 0) {
			D("aborting");
			usage();
		}
    }


	if (g->options) {
		D("--- SPECIAL OPTIONS:%s%s%s",
			g->options & OPT_PREFETCH ? " prefetch" : "",
			g->options & OPT_ACCESS ? " access" : "",
			g->options & OPT_MEMCPY ? " memcpy" : "");
	}

	g->tx_period.tv_sec = g->tx_period.tv_nsec = 0;
	if (g->tx_rate > 0) {
		/* try to have at least something every second,
		 * reducing the burst size to some 0.01s worth of data
		 * (but no less than one full set of fragments)
	 	 */
		uint64_t x;
		int lim = (g->tx_rate)/300;
		if (g->burst > lim)
			g->burst = lim;
		if (g->burst < g->frags)
			g->burst = g->frags;
		x = ((uint64_t)1000000000 * (uint64_t)g->burst) / (uint64_t) g->tx_rate;
		g->tx_period.tv_nsec = x;
		g->tx_period.tv_sec = g->tx_period.tv_nsec / 1000000000;
		g->tx_period.tv_nsec = g->tx_period.tv_nsec % 1000000000;
	}
	if (g->td_body == sender_body)
	    D("Sending %d packets every  %ld.%09ld s",
			g->burst, g->tx_period.tv_sec, g->tx_period.tv_nsec);
	/* Wait for PHY reset. */
	D("Wait %d secs for phy reset", g->wait_link);
	sleep(g->wait_link);
	D("Ready...");
}

/* end of file */
