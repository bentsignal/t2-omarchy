/* Decode one Apple complzvn kernel wrapper with strict size bounds.
 *
 * Build against an implementation of FastCompression.h's lzvn_decode():
 *   cc -O2 -Wall -Wextra -Werror decode-complzvn.c libFastCompression.a -o decode-complzvn
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern size_t lzvn_decode(void *dst, size_t dst_size,
                          const void *src, size_t src_size);

#define HEADER_SIZE 384U
#define MAX_COMPRESSED (256U * 1024U * 1024U)
#define MAX_DECOMPRESSED (512U * 1024U * 1024U)

static int read_all(int fd, void *buffer, size_t size)
{
	uint8_t *cursor = buffer;
	while (size) {
		ssize_t count = read(fd, cursor, size);
		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
			return -1;
		cursor += count;
		size -= (size_t)count;
	}
	return 0;
}

static int write_all(int fd, const void *buffer, size_t size)
{
	const uint8_t *cursor = buffer;
	while (size) {
		ssize_t count = write(fd, cursor, size);
		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
			return -1;
		cursor += count;
		size -= (size_t)count;
	}
	return 0;
}

int main(int argc, char **argv)
{
	uint8_t header[HEADER_SIZE];
	uint8_t *compressed = NULL, *decompressed = NULL;
	uint32_t encoded_size, decoded_size;
	struct stat status;
	int input = -1, output = -1, result = 1;
	size_t actual;

	if (argc != 3) {
		fprintf(stderr, "usage: %s INPUT OUTPUT\n", argv[0]);
		return 2;
	}
	input = open(argv[1], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (input < 0 || fstat(input, &status) || !S_ISREG(status.st_mode)) {
		perror("open input");
		goto out;
	}
	if (read_all(input, header, sizeof(header))) {
		fprintf(stderr, "short complzvn header\n");
		goto out;
	}
	if (memcmp(header, "complzvn", 8)) {
		fprintf(stderr, "invalid complzvn signature\n");
		goto out;
	}
	memcpy(&decoded_size, header + 12, sizeof(decoded_size));
	memcpy(&encoded_size, header + 16, sizeof(encoded_size));
	decoded_size = ntohl(decoded_size);
	encoded_size = ntohl(encoded_size);
	if (!encoded_size || encoded_size > MAX_COMPRESSED ||
	    !decoded_size || decoded_size > MAX_DECOMPRESSED ||
	    (uint64_t)HEADER_SIZE + encoded_size != (uint64_t)status.st_size) {
		fprintf(stderr, "invalid complzvn size fields\n");
		goto out;
	}
	compressed = malloc(encoded_size);
	decompressed = malloc(decoded_size);
	if (!compressed || !decompressed) {
		fprintf(stderr, "allocation failed\n");
		goto out;
	}
	if (read_all(input, compressed, encoded_size)) {
		fprintf(stderr, "short compressed payload\n");
		goto out;
	}
	actual = lzvn_decode(decompressed, decoded_size, compressed, encoded_size);
	if (actual != decoded_size) {
		fprintf(stderr, "decoder returned %zu bytes; expected %u\n",
		        actual, decoded_size);
		goto out;
	}
	if (decoded_size < 4 ||
	    (memcmp(decompressed, "\xcf\xfa\xed\xfe", 4) &&
	     memcmp(decompressed, "\xca\xfe\xba\xbe", 4))) {
		fprintf(stderr, "decoded payload is not a recognized Mach-O\n");
		goto out;
	}
	output = open(argv[2], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
	              0600);
	if (output < 0 || write_all(output, decompressed, decoded_size) || fsync(output)) {
		perror("write output");
		goto out;
	}
	printf("decoded complzvn: compressed=%u decompressed=%u\n",
	       encoded_size, decoded_size);
	result = 0;
out:
	if (output >= 0) {
		close(output);
		if (result)
			unlink(argv[2]);
	}
	if (input >= 0)
		close(input);
	free(decompressed);
	free(compressed);
	return result;
}
