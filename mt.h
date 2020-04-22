#ifndef _MT_H_
#define _MT_H_

//#include "types.h"

struct chunk {
	unsigned long int offset;				// offset w pliku w bajtach do poczaktu tego chunka
	unsigned long int len;					// dlugosc tego chunka
	char sha[20];
	struct node *node;
	enum { CH_EMPTY = 0, CH_ACTIVE } state;
};
 

struct node {
	int number;					// numer wezla
	struct node *left, *right, *parent;		// jesli parent == NULL - to jest to korzen drzwea
	struct chunk *chunk;				// tylko wezly typu liscie maja swoje chunki - figure 2. rfc7574: c0, c1, c2, c3, c4, ...
	char sha[20];
	enum { EMPTY = 0, INITIALIZED, ACTIVE } state;
#if DEBUG
	int l, si;					// tylko dla debuggingu  weryfikacja poziomu (l: 1...l) na ktorym jest wezel i jego index (si: 0..si-1) na danym poziomie
#endif	
};




#endif
