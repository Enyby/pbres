/* 
 *  pbres - theme and resource compiler for PocketBook
 *  Author: Dmitry Zakharov
 *  License: GPL
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <zlib.h>

#define MAXSIZE 520000
#define MAXIMGLIST 4096
#define PBTSIGNATURE "PocketBookTheme"
#define PBTVERSION 1

typedef struct ibitmap_s {

	unsigned short width;
	unsigned short height;
	unsigned short depth;
	unsigned short scanline;
	unsigned char data[];

} ibitmap;

struct imgcache {

	int pos;
	int len;
	unsigned char *data;

};

void warning(char *fmt, ...) {

	va_list ap;

	fprintf(stderr, "Warning: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n\n");

}

void terminate(char *fmt, ...) {

	va_list ap;

	fprintf(stderr, "Error: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n\n");
	exit(1);

}

void usage(void) {

	fprintf(stderr, "Version: 0.4\n");
	fprintf(stderr, "Usage: pbres -c output.c resource [ ... ]\n");
	fprintf(stderr, "       pbres -t output.pbt config.txt resource [ ... ]\n");
	fprintf(stderr, "       pbres -u input.pbt resource\n");
	fprintf(stderr, "       pbres -d input.pbt\n");
	fprintf(stderr, "       pbres -l input.pbt\n");
	exit(1);

}

void write_as_c(FILE *f, unsigned char *data, int len) {

	char buf[1024];
	int i, n, ll;

	while (len > 0) {

		n = (len > 16) ? 16 : len;

		ll = 0;
		ll += sprintf(buf+ll, "\t\t");
		for (i=0; i<n; i++) ll += sprintf(buf+ll, "0x%02x,", data[i]);
		ll += sprintf(buf+ll, "\n");

		if (fwrite(buf, 1, ll, f) != ll) terminate("error writing to file");

		data += n;
		len -= n;

	}

}

ibitmap *bmp2res(char *fname, unsigned char *data, int len, int *outsize) {

	ibitmap *bm;
	unsigned char palette[256];
	unsigned char *pos, c, inv;
	int start, hsize, width, height, bpp, comp, scanlen, scanout, maskout;
	unsigned char *udata, *umask, *inp, *outp, *maskp;
	int ulen, umasklen;
	int i, x, y, usemask;

	if (data[0] != 'B' || data[1] != 'M') terminate("%s is not a bmp file", fname);

	start = *((int *)(data+0x0a));
	hsize = *((int *)(data+0x0e));
	width = *((int *)(data+0x12));
	height = *((int *)(data+0x16));
	bpp = *((short *)(data+0x1c));
	comp = *((int *)(data+0x1e));
	scanlen = ((width * bpp + 7) / 8 + 3) & ~0x3;
	if (bpp == 1) {
		scanout = (width + 7) / 8;
	} else {
		scanout = (width + 3) / 4;
	}
	maskout = (width + 7) / 8;

	if (comp != 0) terminate("%s: compressed bmp files are not supported", fname);

	if (bpp != 1 && bpp != 8) terminate("%s: wrong format (should be 8-bit or 1-bit)", fname);

	// reading palette

	pos = data + 14 + hsize;
	for (i=0; i<256; i++) {
		if (pos > data+len) break;
		c = (pos[0] + pos[1]*6 + pos[2]*3) / 10;
		if (c <= 0x2a) {
			palette[i] = 0;
		} else if (c <= 0x80) {
			palette[i] = 1;
		} else if (c <= 0xd4) {
			palette[i] = 2;
		} else {
			palette[i] = 3;
		}
		if (pos[0] == 64 && pos[1] == 128 && pos[2] == 128) palette[i] = 255; // transparent
		pos += 4;
	}

	ulen = height * scanout;
	umasklen = height * maskout;

	bm = calloc(sizeof(ibitmap) + ulen + umasklen, 1);
	bm->width = width;
	bm->height = height;
	bm->depth = (bpp == 1) ? 1 : 2;
	bm->scanline = scanout;

	udata = bm->data;
	memset(udata, 0, ulen);
	umask = bm->data + ulen;
	memset(umask, 0xff, umasklen);
	usemask = 0;

	for (y=0; y<height; y++) {

		inp = data + start + y * scanlen;
		outp = udata + (height - y - 1) * scanout;
		maskp = umask + (height - y - 1) * maskout;

		if (bpp == 1) {

			inv = (palette[0] < palette[1]) ? 0xff : 0;
			for (i=0; i<scanout; i++) {
				outp[i] = inp[i] ^ inv;
			}

		} else {

			for (x=0; x<width; x++) {
				if (palette[inp[x]] != 255) {
					outp[x>>2] |= palette[inp[x]] << ((3 - (x & 3)) << 1);
				} else {
					usemask = 1;
					maskp[x>>3] &= ~(1 << (7 - (x & 7)));
				}
			}

		}

	}

	if (usemask) bm->depth |= 0x8000;
	*outsize = usemask ? ulen+umasklen : ulen;
	return bm;

}

char *getname(char *s) {

	static char tname[64];
	char *p;

	p = strrchr(s, '/');
	if (p == NULL) p = strrchr(s, '\\');
	if (p != NULL) p++;
	if (p == NULL) p = s;
	strncpy(tname, p, 63);
	p = strchr(tname, '.');
	if (p != NULL) *p = 0;
	return tname;

}

void main_c(char *outfile, int nfiles, char **infiles) {

	unsigned char *data;
	int i, len, size;
	ibitmap *bm;
	FILE *ifd, *ofd;

	data = malloc(MAXSIZE);

	ofd = fopen(outfile, "wb");
	if (ofd == NULL) terminate("Cannot open output file %s", outfile);

	fprintf(ofd, "typedef struct ibitmap_s {\n");
        fprintf(ofd, "\tshort width;\n");
        fprintf(ofd, "\tshort height;\n");
        fprintf(ofd, "\tshort depth;\n");
        fprintf(ofd, "\tshort scanline;\n");
        fprintf(ofd, "\tunsigned char data[];\n");
	fprintf(ofd, "} ibitmap;\n\n");

	for (i=0; i<nfiles; i++) {

		ifd = fopen(infiles[i], "rb");
		if (ifd == NULL) terminate("Cannot open %s", infiles[i]);
		memset(data, 0, MAXSIZE);
		len = fread(data, 1, MAXSIZE, ifd);
		if (len == MAXSIZE) terminate("File %s is too big", infiles[i]);
		fclose(ifd);

		bm = bmp2res(infiles[i], data, len, &size);

		fprintf(ofd, "const ibitmap %s = {\n", getname(infiles[i]));
		fprintf(ofd, "\t%u, %u, %u, %u,\n", bm->width, bm->height, bm->depth, bm->scanline);
		fprintf(ofd, "\t{\n");
		write_as_c(ofd, bm->data, size);
		fprintf(ofd, "\t}\n");
		fprintf(ofd, "};\n\n");

	}

}

void main_t(char *outfile, char *cfgfile, int nfiles, char **infiles) {

	unsigned char *data, *data1, *data2, *header, *hpos;
	unsigned int *iheader;
	int i, j, len, size, headersize, the_same;
	unsigned long clen;
	ibitmap *bm;
	FILE *ifd, *ofd;
	char *fname, *extp;
	struct imgcache *imglist;
	int imgpos;

	data = malloc(MAXSIZE);
	imglist = (struct imgcache *) malloc(MAXIMGLIST * sizeof(struct imgcache));

	ofd = fopen(outfile, "wb");
	if (ofd == NULL) terminate("Cannot open output file %s", outfile);

	ifd = fopen(cfgfile, "rb");
	if (ifd == NULL) terminate("Cannot open configuration file %s", cfgfile);
	len = fread(data, 1, MAXSIZE, ifd);
	if (len == MAXSIZE) terminate("File %s is too big", cfgfile);
	data[len++] = 0;
	clen = len + 16384;
	data2 = malloc(clen);
	compress2 (data2, &clen, data, len, 9);

	headersize = 32;
	for (i=0; i<nfiles; i++) {
		headersize += 12;
		headersize += ((strlen(getname(infiles[i])) / 4) + 1) * 4;
	}

	header = (unsigned char *) malloc(headersize);
	iheader = (int *) header;
	memset(header, 0, headersize);
	strcpy(header, PBTSIGNATURE);
	header[15] = PBTVERSION;
	iheader[4] = headersize;
	iheader[5] = len;
	iheader[6] = headersize;
	iheader[7] = clen;

	fwrite(header, 1, headersize, ofd);
	fwrite(data2, 1, clen, ofd);
	free(data2);

	hpos = header+32;

	imgpos = 0;

	for (i=0; i<nfiles; i++) {

		fname = infiles[i];
		extp = fname + strlen(fname) - 4;
		if (strcasecmp(fname, "thumbs.db") == 0) continue;

		ifd = fopen(fname, "rb");
		if (ifd == NULL) terminate("Cannot open %s", fname);
		memset(data, 0, MAXSIZE);
		len = fread(data, 1, MAXSIZE, ifd);
		if (len == MAXSIZE) terminate("File %s is too big", fname);
		fclose(ifd);

		if (strcasecmp(extp, ".bmp") == 0) {

			bm = bmp2res(fname, data, len, &size);
			data1 = (unsigned char *) bm;
			len = sizeof(ibitmap) + size;

		} else if (strcasecmp(extp, ".ttf") == 0) {

			data1 = data;

		} else {

			data1 = NULL;
			terminate("%s: not a BMP or TTF resource", fname);

		}

		clen = len + 16384;
		data2 = malloc(clen);
		compress2 (data2, &clen, data1, len, 9);


		*((int *) hpos) = len;
		*((int *) (hpos+4)) = ftell(ofd);
		*((int *) (hpos+8)) = clen;

		the_same = 0;
		for (j=0; j<imgpos; j++) {
			if (clen == imglist[j].len && memcmp(data2, imglist[j].data, clen) == 0) {
				*((int *) (hpos+4)) = imglist[j].pos;
				the_same = 1;
				break;
			}
		}
		hpos += 12;
		strcpy(hpos, getname(fname));
		hpos += ((strlen(getname(fname)) / 4) + 1) * 4;

		if (! the_same) {

			if (imgpos < MAXIMGLIST) {
				imglist[imgpos].pos = ftell(ofd);
				imglist[imgpos].len = clen;
				imglist[imgpos].data = malloc(clen);
				memcpy(imglist[imgpos].data, data2, clen);
				imgpos++;
			}
			if (fwrite(data2, 1, clen, ofd) != clen) {
				terminate("Error writing output file");
			}

		}

		free(data2);

	}

	fseek(ofd, 0, SEEK_SET);
	fwrite(header, 1, headersize, ofd);
	fclose(ofd);

}

#define _BYTE  uint8_t
#define _WORD  uint16_t
#define _DWORD uint32_t
#define _QWORD uint64_t

#define LOBYTE(x)   (*((_BYTE*)&(x)))   // low byte
#define LOWORD(x)   (*((_WORD*)&(x)))   // low word
#define LODWORD(x)  (*((_DWORD*)&(x)))  // low dword
#define HIBYTE(x)   (*((_BYTE*)&(x)+1))
#define HIWORD(x)   (*((_WORD*)&(x)+1))
#define HIDWORD(x) (*((_DWORD*)&(x)+1))

char palette_index_four[4] = {0x00, 0x56, 0xAC, 0xFF};

void bmp_from_bm(FILE *ofd, unsigned char *data, int len) {
	//fwrite(data, 1, len, ofd); // default
	
  int v2; // edx@2
  int v3; // eax@2
  int v4; // ebx@2
  signed int v5; // esi@2
  int v6; // eax@6
  size_t v7; // ebx@10
  uint16_t v8; // bx@10
  int v9; // edx@10
  uint16_t v10; // cx@12
  int v11; // esi@14
  int v12; // ebx@16
  int v13; // edi@16
  _BYTE *v14; // edx@16
  int v16; // eax@25
  char *v17; // esi@26
  signed int v18; // edi@26
  char *v19; // ecx@28
  int v20; // eax@28
  int v21; // ebx@28
  char v22; // dl@30
  int v23; // eax@50
  size_t v24; // ebx@51
  int v25; // eax@51
  int v26; // edx@53
  int v27; // edx@57
  char v28; // al@58
  char *i; // [sp+14h] [bp-8Ch]@28
  int v30; // [sp+18h] [bp-88h]@12
  void *v31; // [sp+24h] [bp-7Ch]@2
  _DWORD *v32; // [sp+28h] [bp-78h]@2
  _BYTE *v33; // [sp+2Ch] [bp-74h]@2
  int v34; // [sp+3Ch] [bp-64h]@6
  void *v35; // [sp+40h] [bp-60h]@6
  signed int v36; // [sp+44h] [bp-5Ch]@12
  char v37; // [sp+48h] [bp-58h]@0
  FILE *v38; // [sp+4Ch] [bp-54h]@1
  void *v39; // [sp+50h] [bp-50h]@10
  char *v40; // [sp+54h] [bp-4Ch]@14
  unsigned int v41; // [sp+58h] [bp-48h]@2
  int v42; // [sp+5Ch] [bp-44h]@0
  char v43; // [sp+62h] [bp-3Eh]@2
  char v44; // [sp+63h] [bp-3Dh]@15
  int v45; // [sp+64h] [bp-3Ch]@0
  char v46; // [sp+68h] [bp-38h]@2
  int v47; // [sp+80h] [bp-20h]@14
  int v48; // [sp+84h] [bp-1Ch]@14

  v38 = ofd;
  
  unsigned char *a2 = data;
  
  v33 = malloc(2u);
  v32 = malloc(0xCu);
  *v32 = 0;
  v32[1] = 0;
  v32[2] = 0;
  v31 = malloc(0x28u);
  memset(v31, 0, 0x28u);
  v2 = *(_WORD *)a2;
  v43 = *(_WORD *)(a2 + 4);
  v46 = *(_WORD *)(a2 + 4) >> 15;
  v3 = *(_WORD *)(a2 + 2);
  v41 = (v2 + 3) & 0xFFFFFFFC;
  *v33 = 66;
  v33[1] = 77;
  v4 = v3 * v41;
  *((_DWORD *)v31 + 2) = v3;
  *(_DWORD *)v31 = 40;
  *((_DWORD *)v31 + 1) = v2;
  *((_WORD *)v31 + 6) = 1;
  *((_WORD *)v31 + 7) = 8;
  *((_DWORD *)v31 + 4) = 0;
  *((_DWORD *)v31 + 7) = 166;
  *((_DWORD *)v31 + 6) = 166;
  v5 = 1 << v43;
  *((_DWORD *)v31 + 8) = 1 << v43;
  if ( v46 )
    *((_DWORD *)v31 + 8) = v5 + 1;
  if ( *((_DWORD *)v31 + 8) <= 0xFu )
    *((_DWORD *)v31 + 8) = 16;
  *((_DWORD *)v31 + 9) = 0;
  *((_DWORD *)v31 + 5) = v4;
  v34 = 4 * *((_DWORD *)v31 + 8);
  v35 = malloc(v34);
  v6 = (int)memset(v35, 0, v34);
  switch ( v43 )
  {
    case 4:
      if ( v5 > 0 )
      {
        v26 = 0;
        do
        {
          LOBYTE(v6) = v26;
          v6 = v26 + 16 * v6;
          *((_BYTE *)v35 + 4 * v26) = v6;
          *((_BYTE *)v35 + 4 * v26 + 2) = v6;
          *((_BYTE *)v35 + 4 * v26++ + 1) = v6;
        }
        while ( v26 != v5 );
      }
      break;
    case 2:
      if ( v5 > 0 )
      {
        v27 = 0;
        do
        {
          v28 = palette_index_four[v27];
          *((_BYTE *)v35 + 4 * v27) = v28;
          *((_BYTE *)v35 + 4 * v27 + 2) = v28;
          *((_BYTE *)v35 + 4 * v27++ + 1) = v28;
        }
        while ( v27 != v5 );
      }
      break;
    case 1:
      *(_BYTE *)v35 = 0;
      *((_BYTE *)v35 + 2) = 0;
      *((_BYTE *)v35 + 1) = 0;
      v23 = (int)v35 + 4;
      *((_BYTE *)v35 + 4) = -1;
      *(_BYTE *)(v23 + 2) = -1;
      *(_BYTE *)(v23 + 1) = -1;
      if ( v46 != 1 )
        goto LABEL_10;
      goto LABEL_51;
  }
  if ( v46 != 1 )
  {
LABEL_10:
    v7 = v4 + 16;
    v39 = malloc(v7);
    memset(v39, 0, v7);
    v8 = *(_WORD *)(a2 + 2);
    v9 = *(_WORD *)(a2 + 2);
    goto LABEL_11;
  }
LABEL_51:
  v24 = v4 + 16;
  v25 = (int)v35 + 4 * v5;
  *(_BYTE *)v25 = 64;
  *(_BYTE *)(v25 + 1) = -128;
  *(_BYTE *)(v25 + 2) = -128;
  v39 = malloc(v24);
  memset(v39, 0, v24);
  v8 = *(_WORD *)(a2 + 2);
  v9 = *(_WORD *)(a2 + 2);
  v37 = 1 << v43;
  v45 = a2 + v9 * *(_WORD *)(a2 + 6) + 8;
  v42 = (*(_WORD *)a2 + 7) >> 3;
LABEL_11:
  if ( v9 )
  {
    v36 = 0;
    v10 = *(_WORD *)(a2 + 6);
    v30 = (uint8_t)(v5 - 1);
    do
    {
      if ( v10 )
      {
        v40 = (char *)(a2 + 8 + v36 * v10);
        v48 = 0;
        v47 = (int)v39 + v41 * (v9 - v36 - 1);
        v11 = 8 / (uint8_t)v43;
        while ( 1 )
        {
          v44 = *v40;
          if ( v11 )
          {
            v12 = 0;
            v13 = (uint8_t)(8 - v43);
            v14 = (_BYTE *)v47;
            do
            {
              ++v12;
              *v14++ = (signed int)(uint8_t)(v44 & (v30 << v13)) >> v13;
              v13 += (uint8_t)-v43;
            }
            while ( v12 != v11 );
            v47 += v11;
            v10 = *(_WORD *)(a2 + 6);
          }
          if ( v10 <= ++v48 )
            break;
          ++v40;
        }
        v8 = *(_WORD *)(a2 + 2);
      }
      v9 = v8;
      ++v36;
    }
    while ( v8 > v36 );
  }
  if ( v46 )
  {
    v16 = v8;
    if ( v8 )
    {
      v17 = (char *)v45;
      v18 = 0;
      do
      {
        if ( v42 )
        {
          v19 = v17;
          v20 = (int)v39 + v41 * (v16 - v18 - 1);
          v21 = 0;
          for ( i = v17; ; v19 = i )
          {
            v22 = *v19;
            if ( *v19 >= 0 )
              *(_BYTE *)v20 = v37;
            if ( !(v22 & 0x40) )
              *(_BYTE *)(v20 + 1) = v37;
            if ( !(v22 & 0x20) )
              *(_BYTE *)(v20 + 2) = v37;
            if ( !(v22 & 0x10) )
              *(_BYTE *)(v20 + 3) = v37;
            if ( !(v22 & 8) )
              *(_BYTE *)(v20 + 4) = v37;
            if ( !(v22 & 4) )
              *(_BYTE *)(v20 + 5) = v37;
            if ( !(v22 & 2) )
              *(_BYTE *)(v20 + 6) = v37;
            if ( !(v22 & 1) )
              *(_BYTE *)(v20 + 7) = v37;
            ++v21;
            v20 += 8;
            if ( v21 == v42 )
              break;
            ++i;
          }
          v8 = *(_WORD *)(a2 + 2);
        }
        ++v18;
        v16 = v8;
        v17 += v42;
      }
      while ( v8 > v18 );
    }
  }
  v32[2] = v34 + 54;
  *v32 = *((_DWORD *)v31 + 5) + v34 + 54;
  fwrite(v33, 1u, 2u, v38);
  fwrite(v32, 1u, 0xCu, v38);
  fwrite(v31, 1u, 0x28u, v38);
  fwrite(v35, 1u, v34, v38);
  fwrite(v39, 1u, *((_DWORD *)v31 + 5), v38);

  free(v33);
  free(v32);
  free(v31);
  free(v35);
  free(v39);
}

void unpack_resource(FILE *fd, char *name, unsigned long len, int pos, unsigned long clen, int decode) {

	unsigned char *data, *cdata;
	FILE *ofd;
	int r;

	cdata = malloc(clen);
	data = malloc(len+16);
	memset(cdata, 0, clen);
	memset(data, 0, len+16);
	fseek(fd, pos, SEEK_SET);
	fread(cdata, 1, clen, fd);
	r = uncompress (data, &len, cdata, clen);
	if (r != Z_OK) {
		terminate("decompression error");
	}
	ofd = fopen(name, "wb");
	if (ofd == NULL) terminate("Cannot open output file %s", name);
	if (decode) {
		bmp_from_bm(ofd, data, len);
	} else {
		fwrite(data, 1, len, ofd);
	}
	fclose(ofd);
	free(cdata);
	free(data);

}

void main_u(char *themefile, char *resource) {

	char buf[32];
	unsigned char *header, *hpos;
	unsigned int *iheader;
	int pos, headersize;
	unsigned long len, clen;
	FILE *tfd;

	tfd = fopen(themefile, "rb");
	if (tfd == NULL) terminate("Cannot open theme file %s", themefile);

	memset(buf, 0, 32);
	fread(buf, 1, 32, tfd);
	if (strncmp(buf, PBTSIGNATURE, strlen(PBTSIGNATURE)) != 0) terminate("%s is not a PocketBook theme file");
	headersize = *((int *) (buf+16));
	header = malloc(headersize);
	iheader = (int *) header;
	fseek(tfd, 0, SEEK_SET);
	fread(header, 1, headersize, tfd);

	hpos = header+32;

	if (strcmp(resource, "-") == 0) {
		unpack_resource(tfd, "theme.cfg", iheader[5], iheader[6], iheader[7], 0);
		return;
	}

	while (hpos < header+headersize) {

		if (strcmp(hpos+12, resource) == 0) {

			len = *((int *) hpos);
			pos = *((int *) (hpos+4));
			clen = *((int *) (hpos+8));
			unpack_resource(tfd, hpos+12, len, pos, clen, 0);
			return;

		}

		hpos += 12;
		hpos += ((strlen(hpos) / 4) + 1) * 4;

	}

	terminate("resource %s is not found in %s", resource, themefile);

}

void main_d(char *themefile) {

	char buf[32];
	unsigned char *header, *hpos, *hname;
	unsigned int *iheader;
	int pos, headersize;
	unsigned long len, clen;
	FILE *tfd;

	tfd = fopen(themefile, "rb");
	if (tfd == NULL) terminate("Cannot open theme file %s", themefile);

	memset(buf, 0, 32);
	fread(buf, 1, 32, tfd);
	if (strncmp(buf, PBTSIGNATURE, strlen(PBTSIGNATURE)) != 0) terminate("%s is not a PocketBook theme file");
	headersize = *((int *) (buf+16));
	header = malloc(headersize);
	iheader = (int *) header;
	fseek(tfd, 0, SEEK_SET);
	fread(header, 1, headersize, tfd);

	hpos = header+32;
	
	int ind = strlen(themefile);
	themefile[ind - 4] = '\0';
	
	mkdir(themefile, 0777);
	
	char buff[1024];
	memset(&buff[0], 0, sizeof(buff));
	
	snprintf(&buff[0], sizeof(buff), "%s/res", themefile);
	mkdir(&buff[0], 0777);
	
	snprintf(&buff[0], sizeof(buff), "%s/res4bpp", themefile);
	mkdir(&buff[0], 0777);
	
	snprintf(&buff[0], sizeof(buff), "%s/theme.cfg", themefile);

	// out .cfg
	printf("resource                                               size     compressed\n");
	printf("--------------------------------------------------------------------------\n");
	unpack_resource(tfd, &buff[0], iheader[5], iheader[6], iheader[7], 0);	
	printf("%-50s %8i      %8i\n", &buff[0], iheader[5], iheader[7]);

	while (hpos < header+headersize) {

		{
			len = *((int *) hpos);
			pos = *((int *) (hpos+4));
			clen = *((int *) (hpos+8));			
			// hpos+12 - name char
			hname = strdup(hpos+12);
			int hlen = strlen(hname);
			if (hname[hlen - 1] == '4' && hname[hlen - 2] == ':') {
				hname[hlen - 2] = '\0';
				snprintf(&buff[0], sizeof(buff), "%s/res4bpp/%s.bmp", themefile, hname);
			} else {
				snprintf(&buff[0], sizeof(buff), "%s/res/%s.bmp", themefile, hname);
			}
			unpack_resource(tfd, &buff[0], len, pos, clen, 1);
			printf("%-50s %8i      %8i\n", &buff[0], (int)len, (int)clen);
			free(hname);
		}

		hpos += 12;
		hpos += ((strlen(hpos) / 4) + 1) * 4;
	}
	printf("\n");	
}

void main_l(char *themefile) {

	char buf[32];
	unsigned char *header, *hpos;
	unsigned int *iheader;
	int headersize;
	unsigned long len, clen;
	FILE *tfd;

	tfd = fopen(themefile, "rb");
	if (tfd == NULL) terminate("Cannot open theme file %s", themefile);

	memset(buf, 0, 32);
	fread(buf, 1, 32, tfd);
	if (strncmp(buf, PBTSIGNATURE, strlen(PBTSIGNATURE)) != 0) terminate("%s is not a PocketBook theme file");
	headersize = *((int *) (buf+16));
	header = malloc(headersize);
	iheader = (int *) header;
	fseek(tfd, 0, SEEK_SET);
	fread(header, 1, headersize, tfd);

	hpos = header+32;

	printf("resource                 size     compressed\n");
	printf("--------------------------------------------\n");
	printf("<theme.cfg>          %8i      %8i\n", iheader[5], iheader[7]);

	while (hpos < header+headersize) {

		len = *((int *) hpos);
		clen = *((int *) (hpos+8));
		printf("%-20s %8i      %8i\n", hpos+12, (int)len, (int)clen);

		hpos += 12;
		hpos += ((strlen(hpos) / 4) + 1) * 4;

	}
	printf("\n");

}

int main(int argc, char **argv) {


	if (argc < 3) usage();

	if (strcmp(argv[1], "-c") == 0) {
		if (argc < 4) usage();
		main_c(argv[2], argc-3, &argv[3]);
	} else if (strcmp(argv[1], "-t") == 0) {
		if (argc < 4) usage();
		main_t(argv[2], argv[3], argc-4, &argv[4]);
	} else if (strcmp(argv[1], "-u") == 0) {
		if (argc < 4) usage();
		main_u(argv[2], argv[3]);
	} else if (strcmp(argv[1], "-d") == 0) {
		if (argc < 3) usage();
		main_d(argv[2]);
	} else if (strcmp(argv[1], "-l") == 0) {
		main_l(argv[2]);
	} else {
		usage();
	}

	return 0;


}
