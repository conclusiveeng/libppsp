#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "mt.h"
#include "sha1.h"
#include "ppspp_protocol.h"
#include "net.h"
#include "peer.h"


struct node *tree, *root8, *root16, *root32, *root64;
struct node **tab_tree8, **tab_tree16, **tab_tree32, **tab_tree64;
struct chunk *tab_chunk;

struct peer remote_peer;

void interval_min_max (struct node *i, struct node *min, struct node *max);
void dump_tree (struct node *t, int l);
void dump_tree_raw (struct node **t, int l);



struct node *alloc_init_node(void)
{
	struct node *n;
	n = (struct node *)malloc(sizeof(struct node));
	if (n == NULL)
		return NULL;
	n->number = -1;				// nieuzywany jeszcze node
	n->left = n->right = n->parent = NULL;
	n->chunk = NULL;
	
	return n;
}





// ta proc chyba nie jest uzywana
struct chunk *alloc_init_chunk(void)
{
	struct chunk *c;
	c = (struct chunk *)malloc(sizeof(struct chunk));
	if (c == NULL)
		return NULL;
	memset(c->sha, 0, sizeof(c->sha));
	c->node = NULL;
	
	return c;
}

// zwraca rzad wielksoci binarnej
int order2 (unsigned int val)
{
	int b, o, bits;
	
	o = -1;
	bits = 0;
	for (b = 31; b >= 0; b--) {
		if (val & (1 << b)) {
			if (o == -1) {
				o = b;
			}
			bits++;
		}
	}
	
	if (bits > 1) o++;		// jesli poza calkeim lewym bitem sa na prawo od niego inne bity - zwieksz rzad wielkosci zwracanej w return
	return o;
}



// idz w dol drzewa: LRL- czyli left, right, left
void traverse_ex1 (struct node *t)
{
	struct node *c;
	
	c = t;
	printf("num: %u\n", c->number);
	
	c = c->left;
	printf("num: %u\n", c->number);

	c = c->right;
	printf("num: %u\n", c->number);

	c = c->left;
	printf("num: %u\n", c->number);
}


// idz w dol: RRR
void traverse_ex2 (struct node *t)
{
	struct node *c;
	
	c = t;
	printf("num: %u\n", c->number);
	
	c = c->right;
	printf("num: %u\n", c->number);

	c = c->right;
	printf("num: %u\n", c->number);

}




void traverse_ex3 (struct node *t)
{
	struct node *c;
	
	c = t;
	printf("num: %u\n", c->number);
	
	c = c->right;
	printf("num: %u\n", c->number);

	c = c->right;
	printf("num: %u\n", c->number);

	c = c->right;
	printf("num: %u\n", c->number);
	
	c = c->right;
	printf("num: %u\n", c->number);
	
}


// tymczasowo nie uzywana jest *a[]
struct node * build_tree (struct chunk *a[], int num_chunks, struct node **ret)
{
	int x, l, s, si, h, first_idx, nc;
	int left, right, parent, root_idx;
	struct node *rot, *tt;
	
//	printf("num_chunks: %u   tree: %#x\n", num_chunks, t);
	printf("num_chunks: %u\n", num_chunks);



	h = order2(num_chunks);							// "h" - height - wysokosc drzewka
	nc = 1 << h;								// jesli jest tylko sciagnietych np. 7 chunkow - to trzeba przyjac drzewko o 1 rzad wieksze dla pomieszczenia tych chunkow - czyli tak jakby chunkow bylo 8
	printf("order2(%u): %u\n", num_chunks, h);
	printf("num_chunks(orig): %u  after_correction: %u\n", num_chunks, nc);
	

// ok to dobrze listuje drzewko (tylko listuje)
#if 1
	for (l = 1; l <= h + 1; l++) {		// idz po poziomach drzewa od dolu- "l" level
		first_idx = (1 << (l - 1)) -1;  // pierwszy index na danym poziomie od lewej: 0, 1, 3, 7, 15, etc
		for (si = first_idx; si < 2 * nc; si += (1 << l)) {   //si - sibling index
			printf("%u ", si);
		}
		printf("\n");
	}
#endif	
	
	
	
	// alokuj tablice indexow dla drzewka
	tt = malloc(2 * nc * sizeof(struct node));
	
	//alokuj pamiec dla wszystkich wezlow -
	for (x = 0; x < 2 * nc; x++) {
		//tt[x] = alloc_init_node();
		tt[x].number = x;
		tt[x].chunk = NULL;
		tt[x].left = tt[x].right = tt[x].parent = NULL;
		tt[x].state = INITIALIZED;
		//printf("alloc: %u\n", x);
		//printf("x: %u\n", x);
	}
	
	
	// sprawdzic czy root-node blednie nie ma rodzica - bo nie powinien miec
	printf("\nlaczenie wezlow czyli tworzenie drzewka\n\n");
	for (l = 1; l <= h; l++) {		// idz po poziomach drzewa od dolu- "l" level
		first_idx = (1 << (l - 1)) -1;  // pierwszy index na danym poziomie od lewej: 0, 1, 3, 7, 15, etc
		for (si = first_idx; si < 2 * nc; si += (2 << l)) {   //si - sibling index
			left = si;
			right = (si | (1 << l));
			parent = (left + right) / 2;
			//printf("para %u-%u bedzie miec rodzica: %u\n", left, right, parent);
			tt[left].parent = &tt[parent];			// rodzic dla lewego wezla
			tt[right].parent = &tt[parent];			// rodzic dla prawego wezla
			
			tt[parent].left = &tt[left];			// lewe dziecko rodzica
			tt[parent].right = &tt[right];			// prawe dziecko rodzica
		}
		//printf("\n");
	}
	
	
	
	
	
	*ret = tt;
	
	
	//todo - przypisac lisciom chunki
	
	
	
	root_idx = (1 << h) - 1;
	printf("root node: %u\n", root_idx);
	
	rot = &tt[root_idx];
	return rot;
	
}






// rozszerzenia drzewka o jeden rzad: np. 2->4 lub 4->8, lub 8->16 lisci
// num_chunks - aktualna ilosc chunkow oryginalnego drzewa do rozszerzenia, czyli przed rozszerzeniem czyli mniejsza wartosc

// a moze num chunks procedura powinna sama sobie wyliczac?
struct node * extend_tree (struct chunk *a[], struct node *orig_tree, int num_chunks, struct node **ret)
{
	int x, l, s, si, h, first_idx, nc, nn;
	int left, right, parent, root_idx;
	struct node *rot, *tt;
	int root_idx_012, root_idx_456;
	struct node min, max;


//	printf("num_chunks: %u   tree: %#x\n", num_chunks, t);
	printf("extending tree - num_chunks: %u => %u\n", num_chunks, num_chunks * 2);



	h = order2(num_chunks);					// "h" - height - wysokosc drzewka
	nc = 1 << h;						// jesli jest tylko sciagnietych np. 7 chunkow - to trzeba przyjac drzewko o 1 rzad wieksze dla pomieszczenia tych chunkow - czyli tak jakby chunkow bylo 8
	printf("order2(%u): %u\n", num_chunks, h);
	printf("num_chunks(orig): %u  after_correction: %u\n", num_chunks, nc);
	

// ok to dobrze listuje drzewko (tylko listuje)
#if 0
	for (l = 1; l <= h + 1; l++) {		// idz po poziomach drzewa od dolu- "l" level
		first_idx = (1 << (l - 1)) -1;  // pierwszy index na danym poziomie od lewej: 0, 1, 3, 7, 15, etc
		for (si = first_idx; si < 2 * nc; si += (1 << l)) {   //si - sibling index
			printf("%u ", si);
		}
		printf("\n");
	}
#endif	
	
	
	
	// alokuj tablice indexow dla drzewka - dla calego nowego?
	tt = malloc(2 * 2 * nc * sizeof(struct node));		// musi byc o 1 rzadz wieksza tablica - czyli 2 razy wieksza - stad poczatkowe 2*
	*ret = tt;
	
	//alokuj pamiec tylko dla nowych wezlow (alloc_init_node), czyli np. dla nowego drzewka 0123456, alokuj tylko 3456
	
#if 1
	// 2020.04.18 - czy tu na pewno ma byc for od 2*nc? chyba raczej dla wsyzsktich node-ow bo to cale nowe drzewko
//	for (x = 2 * nc; x < 2 * 2 * nc; x++) {
	for (x = 0; x < 2 * 2 * nc; x++) {

			//tt[x] = alloc_init_node();
//			printf("nowa alokacja node'ow (rozszerzenie): %u:  %#x\n", x, tt[x]);
		
			tt[x].number = x;
			tt[x].chunk = NULL;
			tt[x].left = tt[x].right = tt[x].parent = NULL;
			tt[x].state = INITIALIZED;
//		}
	}
#endif	
	
	
	
	
	
	
	
	// tu skopiuj oryginalna tablice 012 do nowej 0123456
	nn = 2 * nc;
	printf("\n\nnn: %u\n", nn);
	
	//skopiuj tylko sha, bo reszta pol node bedzie odtworzona za chwile (chyba)
	// ale ale - powyzej juz to inicjujemy number, chunk, etc!
//	for (x = 0; x < nn; x++) {
	for (x = 0; x < nc; x++) {
		memcpy(tt[x].sha, orig_tree[x].sha, 20);
	}

	
	
	
	
	// przelicz wielkosci dla nowego drzewka
	h++;
	nc = 2 * nc;

	
	// tu tez tylko dla nowych wezlow - ale nie starej tablicy 012

	interval_min_max(&orig_tree[(1 << (h - 1)) - 1], &min, &max);		//0-14, 16-30
	
#if 1
	printf("\nextend: laczenie wezlow czyli tworzenie drzewka\n\n");
	for (l = 1; l <= h; l++) {		// idz po poziomach drzewa od dolu- "l" level
		first_idx = (1 << (l - 1)) -1;  // pierwszy index na danym poziomie od lewej: 0, 1, 3, 7, 15, etc
		for (si = first_idx; si < 2 * nc; si += (2 << l)) {   //si - sibling index
//			if (si >= nn) {						 // poprawic to 16! albo 15?
			if (1) {						 // poprawic to 16! albo 15?
				left = si;
				right = (si | (1 << l));
				parent = (left + right) / 2;
				//printf("ext para %u-%u bedzie miec rodzica: %u\n", left, right, parent);
				tt[left].parent = &tt[parent];			// rodzic dla lewego wezla
				tt[right].parent = &tt[parent];			// rodzic dla prawego wezla
				
				tt[parent].left = &tt[left];			// lewe dziecko rodzica
				tt[parent].right = &tt[right];			// prawe dziecko rodzica
				
#if 0
				if (l == 1) {
					printf("ext lisc lewy %u:  %#x  %#x\n", left, tt[left].left, tt[left].right);
					printf("ext lisc prawy %u:  %#x  %#x\n", right, tt[right].left, tt[right].right);
				}
#endif
				
			}
		}
		//printf("\n");
	}
#endif	


	


//	dump_tree(tt, 2);
//	dump_tree(tt, 8);
//	dump_tree_raw(tt, 16);
	
	
	
	// polacz oba drzewka - wspolnym rootem
	
	root_idx_012 = (1 << (h - 1)) - 1;
//	root_idx_456 = parent;				// tu parent jest wartosci koncowa z petli for powyzej - i czassami zle liczy

	
	int fi, li; /// first_idx, last_idx - na danym poziomie
//	printf("\n\n\n-------------------------oblicz parent\n\n");
	//fi = first_idx = (1 << (1 - 1)) -1;
//	printf("++++ %u  %u\n", h, root_idx_012 + (1 << (h)));
	root_idx_456 = root_idx_012 + (1 << h);
	

	root_idx = (1 << h) - 1;
	
	// 7 i 23 polaczyc w 15?
//	printf("root012:  %u   root456: %u\n", root_idx_012, root_idx_456);
//	printf("parent: %u\n", parent);
	
	
	tt[root_idx_012].parent = &tt[root_idx];			// rodzic dla lewego wezla
	tt[root_idx_456].parent = &tt[root_idx];			// rodzic dla prawego wezla
	
	tt[root_idx].left = &tt[root_idx_012];			// lewe dziecko rodzica
	tt[root_idx].right = &tt[root_idx_456];			// prawe dziecko rodzica

	tt[root_idx].number = root_idx;
	// brakuje jeszcze tutaj wyliczenie sha dla nowoutworzonego root-a
	
	
	
	
	
	//todo - przypisac lisciom chunki
	
	
	// zwolnic pamiec starego drzewka 012
	free(orig_tree);

	
//	printf("extend root node: %u\n", root_idx);
	printf("extend root node: %u  %u\n", root_idx, tt[root_idx].number);
	
	rot = &tt[root_idx];
	return rot;
}









int update_chunk (struct node *t, unsigned int cn, struct chunk *c)
{
	return 0;
}











// ta proc chyba nie jest wogole nigdzie uzywana
#if 0
void show_tree_tab_based (struct chunk *a[], int num_chunks)
{
	int x, l, s, si, h, first_idx, nc;
	
	printf("num_chunks: %u\n", num_chunks);


	h = order2(num_chunks);							// "h" - height - wysokosc drzewka
	nc = 1 << h;								// jesli jest tylko sciagnietych np. 7 chunkow - to trzeba przyjac drzewko o 1 rzad wieksze dla pomieszczenia tych chunkow - czyli tak jakby chunkow bylo 8
	printf("order2(%u): %u\n", num_chunks, h);
	printf("num_chunks(orig): %u  after_correction: %u\n", num_chunks, nc);
	

// ok to dobrze listuje drzewko (tylko listuje)
#if 1
	for (l = 1; l <= h + 1; l++) {		// idz po poziomach drzewa od dolu- "l" level
		first_idx = (1 << (l - 1)) -1;  // pierwszy index na danym poziomie od lewej: 0, 1, 3, 7, 15, etc
		for (si = first_idx; si < 2 * nc; si += (1 << l)) {   //si - sibling index
			printf("%u ", si);
		}
		printf("\n");
	}
#endif	
}
#endif




/*
 * listuje drzewko - u gory korzen, na dole liscie - czyli na odwrot niz show_tree_tab_based()
 */
void show_tree_root_based (struct node *t)
{
	int l, si, nl, h, nn, ti, first_idx;
	struct node min, max;
	char pre[16], post[16];
	
	printf("listowanie drzewka od roota: %u\n", t->number);
	
	ti = t->number;
	interval_min_max(t, &min, &max);
	printf("min: %u   max: %u\n", min.number, max.number);
	nl = (max.number - min.number) / 2 + 1;		// number of leaves in given subtree
	nn = max.number - min.number + 1;		// number of nodes in subtree
	h = order2(nl) + 1;

	printf("nl: %u  nn: %u  h: %u\n", nl, nn, h);
	
	first_idx = ti;
//	printf("%2u\n", ti);				// numer/index roota



	printf("\n\n");

	
// proba justowania wezlow - na razie tylko dla dwucyfrowych numerow wezlow
#if 1
	int center, iw, m, sp, is;				// iw - ilosc wezlow do wyswietlenia na danym poziomie, m- miejsce w bajtach ktore zajmuje linia z numerami wezlow, sp -ilopsc spacji do wstawienia, is - interspacja - pomiedzy poszczegolnymi wartosciami na danym poziomie
	
	first_idx = ti;
	
	center = (nl * (2 + 2)) / 2;  //2 cyfry i 2 spacje na poziomie lisci - a center to pozycja pozioma (kolumna) do ktorej justowane bedzie drzewko - od wezla root
	for (l = h; l >= 1; l--) {
		is = 1 << (l );			// interspacja - czyli ile spacji ma byc miedzy poszczegolnymi wartosciami na danym poziomie
		iw = 1 << (h - l);
		m = iw * (2 + is) - is;
		//center - m /2 - chyba tyle spacji trzeba wstepnie wstawic 
		//printf("center: %u  iw: %u  m: %u  is: %u\n", center, iw, m, is);
		for (sp = 0; sp < (center - m/2); sp++) printf(" ");
		for (si = first_idx; si <= max.number; si += (1 << l)) { 			// poprawic koncowy warunek
			memset(pre, 0, sizeof(pre));
			memset(post, 0, sizeof(post));
			if (si == 10) {					// przykladowy index do podswietlenia na niebiesko
				sprintf(pre, "\033[0;37;44m");
				sprintf(post, "\033[0m");
			}
			printf("%s%2u%s", pre, si, post);
			for (sp = 0; sp < is; sp++) printf(" ");		//dodaj interspacje
		}
		first_idx -= (1 << (l - 2));
		printf("\n");
	}
#endif

}



// dla drzewka o rootcie "t" znajdz wujka dla wezla "n"
struct node * find_uncle (struct node *t, struct node *n)
{
	struct node *p, *gp, *u;
	
	
	p = n->parent;
	if (p == NULL)
		return NULL;
	gp = p->parent;
	if (gp == NULL)
		return NULL;
	
//	printf("rodzicem dla %u jest %u\n", n->number, p->number);
//	printf("dziadkiem dla %u jest %u\n", n->number, gp->number);

	if (p == gp->right)		// jesli rodzic jest prawym dzieckiem dziadka - to wujek jest lewym dzieckiem dziadka
		u = gp->left;
	if (p == gp->left)		// jesli rodzic jest prawym dzieckiem dziadka - to wujek jest lewym dzieckiem dziadka
		u = gp->right;
	
//	printf("wujkiem dla %u jest %u\n", n->number, u->number);
	printf("wezel: %u   rodzic: %u  dziadek: %u  wujek: %u\n", n->number, p->number, gp->number, u->number);
	
	return u;
}



// metoda iteracyjna (a nie rekurencyjna)
// znajduje minimalny i maxymalny index - schodzac calkiem w lewo w dol od korzenia i calekiem w prawo
void list_interval (struct node *i)
{
	struct node *c, *min, *max;

	c = i;
	while (c->left != NULL) {
		c = c->left;
	}
	min = c;
	

	c = i;
	while (c->right != NULL) {
		c = c->right;
	}
	max = c;


	printf("root: %u  interval  min: %u  max: %u\n", i->number, min->number, max->number);
}


void interval_min_max (struct node *i, struct node *min, struct node *max)
{
	struct node *c;

	c = i;
	while (c->left != NULL) {
	//	printf("c->number: %u\n", c->number);
		c = c->left;
	}
	//*min = c;
	memcpy(min, c, sizeof(struct node));
//	printf("min znalezione: %u\n", min->number);
	

	c = i;
	while (c->right != NULL) {
		c = c->right;
	}
	//*max = c;
	memcpy(max, c, sizeof(struct node));

//	printf("max znalezione: %u\n", max->number);
	
	printf("root: %u  interval  min: %u  max: %u\n", i->number, min->number, max->number);
}


// dumpuj tablice drzewka
void dump_tree (struct node *t, int l)
{
	int x, y, s;
	char shas[40];	
	
	printf("dump tree: %#x\n", t);
	for (x = 0; x < 2 * l; x++) {
		s = 0;
		for (y = 0; y < 20; y++)
			s += sprintf(shas + s, "%02x", t[x].sha[y] & 0xff);
		printf("[%3u]  %u  %s\n", t[x].number, t[x].state, shas);
	}
	printf("\n");
}


// dumpuje adresy z tablicy
void dump_tree_raw (struct node **t, int l)
{
	int x;
	
	printf("dump tree raw: %#x\n", t);
	for (x = 0; x < 2 * l; x++) {
		printf("%#x\n", t[x]);
	}
	printf("\n");
}



// dumpowanie tablicy chunkow - czyli wyswietlanie sha
void dump_chunk_tab (struct chunk *c, int l)
{
	int x, y, s;
	char buf[40 + 1];
	
	printf("%s l: %u\n", __FUNCTION__);
	for (x = 0; x < l; x++) {
		s = 0;
		for (y = 0; y < 20; y++) {
			s += sprintf(buf + s, "%02x", c[x].sha[y] & 0xff);
		}
		buf[40] = '\0';
		printf("chunk[%3u]  off: %8u  len: %8u  sha: %s  state: %s\n", x, c[x].offset, c[x].len, buf, c[x].state == CH_EMPTY ? "EMPTY" : "ACTIVE" );
		
	}
}






// dla debuggingu mozna do kazdego node dodac numer poziomu h, i index w tym poziomie do latwego obliczenia numeru indexu ktory powinien dany node zajac w tablicy
void verify_tree1 (struct node *t, int l)
{
	int x;
	
	
	for (x = 0; x < l; x++) {
		if (x != t[x].number) {
			printf("%u: %u\n", x, t[x].number);
			abort();
		}
	}

}


// rekurencyjnie przejdz po wszystich wezlach - zaczynajac od root-a
// i oblicz index danego wezle w tablicy - ale to chyba nie bedzie proste
// (adres_aktualnego_wezla_t - poczatek_tablicy_wezlow) / wielkosc_wezla - da index w tablicy
void verify_tree2 (struct node *t, struct node *array)
{
	int l, h, si, off, idx;
	//struct node *c;


	printf("node: %u\n", t->number);
	// tu wlasciwa weryfikacja
	
	idx = t - array;
	//idx = off / sizeof(struct node);
	
	printf("idx:  %u\n", idx);
/*	
	for (l = 1; l <= h + 1; l++) {		// idz po poziomach drzewa od dolu- "l" level
		first_idx = (1 << (l - 1)) -1;  // pierwszy index na danym poziomie od lewej: 0, 1, 3, 7, 15, etc
		for (si = first_idx; si < 2 * nc; si += (1 << l)) {   //si - sibling index
			printf("%u ", si);
		}
		printf("\n");
	}
*/
	//l = t->l;
	//si = 

	if ((t->left == NULL) || (t->right == NULL)) {
		//printf("koniec rekurencji\n");
		printf("\n");
		return;
	}
	verify_tree2(t->left, array);
	verify_tree2(t->right, array);
}



void update_sha (struct node *t, int num_chunks)
{
	int h, nc, l, si, first_idx, y, s;
	int left, right, parent;
	char sha_left[40 + 1], sha_right[40 + 1], concat[80 + 1], sha_parent[40 + 1];
	SHA1Context context;
	unsigned char digest[20 + 1];

	
	printf("%s\n", __FUNCTION__);

	h = order2(num_chunks);							// "h" - height - wysokosc drzewka
	nc = 1 << h;								// jesli jest tylko sciagnietych np. 7 chunkow - to trzeba przyjac drzewko o 1 
	
	for (l = 1; l <= h; l++) {		// idz po poziomach drzewa od dolu- "l" level
		first_idx = (1 << (l - 1)) -1;  // pierwszy index na danym poziomie od lewej: 0, 1, 3, 7, 15, etc
		for (si = first_idx; si < 2 * nc; si += (2 << l)) {   //si - sibling index
			left = si;
			right = (si | (1 << l));
			parent = (left + right) / 2;
			//printf("para %u-%u ma rodzica: %u\n", left, right, parent);

			// wyznacz string sha dla lewego
			s = 0;
			for (y = 0; y < 20; y++)
				s += sprintf(sha_left + s, "%02x", t[left].sha[y] & 0xff);
			sha_left[40] = '\0';
			//printf(" l: %s\n", sha_left);
			
			// wyznacz string sha dla prawego
			s = 0;
			for (y = 0; y < 20; y++)
				s += sprintf(sha_right + s, "%02x", t[right].sha[y] & 0xff);
			//printf(" r: %s\n", sha_right);
			sha_right[40] = '\0';
			
			sprintf(concat, "%s%s", sha_left, sha_right);
			//printf(" +: %s\n", concat);

			SHA1Reset(&context);
			SHA1Input(&context, concat, 40);
			SHA1Result(&context, digest);


			// skopiuj wyliczone sha do rodzica
			memcpy(t[parent].sha, digest, 20);
			
			// wyznacz string sha dla rodzica
			s = 0;
			for (y = 0; y < 20; y++)
				s += sprintf(sha_parent + s, "%02x", digest[y] & 0xff);
			//printf(" p: %s\n", sha_parent);
			sha_parent[40] = '\0';
			
			t[parent].state = ACTIVE;
		}
		printf("\n");
	}
}





int main (int argc, char *argv[])
{
	struct chunk *c0, *c1;
	struct chunk *tab[4];
	struct node *u;
	struct node *ret, *ret2;
	int x, size, fd, r, nc, nl, c;
	char *fname;
	struct stat stat;
	SHA1Context context;
	unsigned char digest[16];
	unsigned int rd;
	char *buf;
	int opt, chunk_size;
	
	
	chunk_size = 1024;
	fname = NULL;
	while ((opt = getopt(argc, argv, "f:s:")) != -1) {
		switch (opt) {
			case 'f':				// filename
				fname = optarg;
				break;
			case 's':				// chunk size [bytes]
				chunk_size = atoi(optarg);
				break;

			default:
				break;
		}
	}
	
	
	
	printf("chunk_size: %u\n", chunk_size);
	printf("fname: %s\n", fname);
	
	
//	tree = (struct chunk *)malloc(sizeof(struct chunk));
//	c0 = (struct chunk *)malloc(sizeof(struct chunk));
//	c1 = (struct chunk *)malloc(sizeof(struct chunk));

	tree = alloc_init_node();
	c0 = alloc_init_chunk();
	c1 = alloc_init_chunk();
	tab[0] = c0;
	tab[1] = c1;
	tab[2] = NULL;
	tab[3] = NULL;
	
	
	
	
	root8 = build_tree(tab, 8, &ret);		//8 - liczba lisci

	ret2 = ret;


	// rozszerz drzewko 
	root16 = extend_tree(tab, ret2, 8, &ret);		// rozszerz tablice, bez param tt

//	verify_tree2(root16, ret);	
	
	ret2 = ret;
	root32 = extend_tree(tab, ret2, 16, &ret);		// 16 => 32
	
	ret2 = ret;
	root32 = extend_tree(tab, ret2, 32, &ret);		// 32 => 64

	ret2 = ret;




	
//	traverse_ex1(root8);			// przejdz po drzewku - sposob1
//	traverse_ex2(root);			// przejdz po drzewku - sciezka2

//	traverse_ex3(root16);			// przejdz po drzewku - sposob1
	
	
/*
	u = find_uncle(root, tab_tree[9]);	// wujek: 3
	u = find_uncle(root, tab_tree[13]);	// wujek: 3
	u = find_uncle(root, tab_tree[11]);	// brak wujka
	if (u == NULL)
		printf("brak wujka\n");

	u = find_uncle(root, tab_tree[1]);	// wujek: 11
	u = find_uncle(root, tab_tree[2]);	// wujek: 5
*/
	
	//add_chunks();
	
	
	// find/list interval
/*	
	list_interval(tab_tree8[7]);		// od 7-ki czyli listuj cale drzewko
	list_interval(tab_tree8[3]);		// od 3-ki - powinno byc: 0-6
	list_interval(tab_tree8[9]);		// od 9-ki - powinno byc: 8-10
	list_interval(tab_tree8[6]);		// od 6-ki - powinno byc: 6-6
*/

	list_interval(&ret[7]);			// od 7-ki - powinno byc: 0-30
	list_interval(&ret[15]);		// od 15-ki - powinno byc: 0-30
	list_interval(&ret[21]);		// od 21
	list_interval(&ret[31]);		// od 31 - 0-62?
	list_interval(&ret[63]);		// od 31 - 0-126
	
	
//	show_tree_root_based(tab_tree8[7]);	// tylko dla drzewek >=8 
	show_tree_root_based(&ret[7]);	// tylko dla drzewek >=8 



//	show_tree_root_based(ret[23]);
	show_tree_root_based(&ret[15]);				// po extended z 8 do 16
//	show_tree_root_based(&ret[31]);				// po extended z 8 do 16
//	show_tree_root_based(&ret[63]);				// po extended z 8 do 16
	
	
//	show_tree_test(tab_tree[7], 1);
	
//	dump_tree(tab_tree8, 8);
//	dump_tree(tab_tree16, 8);
//	dump_tree(ret, 8);
//	dump_tree(ret, 64);			// dla 64 lisci
	


	// test kiedy sie wysypie extend_tree()
#if 0
	x = 0;
	size = 64;
	while ((x < 30) && (size < 33554432)) {
		ret2 = ret;
		printf("\n\n\nsize: %u\n", size);
		root32 = extend_tree(tab, ret2, size, &ret);		// 32 => 64
		printf("root32: %u\n", root32->number);
		verify_tree1(ret, 2 * size);
		//printf("verify2:\n");
		//verify_tree2(root32);
		//show_tree_root_based(root32);
		size *= 2;
		getc(stdin);
		x++;
	}
#endif
	
	
	
	
	
	
	
	
// przykladowe obliczenie sha1 z pliku podanego jako argv[1]	
	if (fname != NULL) {
		fd = open(fname, O_RDONLY);
		if (fd < 0) {
			printf("error opening file: %s\n", fname);
			//printf("error opening file: %s\n", argv[1]);
			exit(1);
		}
		fstat(fd, &stat);
		printf("file size: %u\n", stat.st_size);
		
		buf = malloc(chunk_size);


		nc = stat.st_size / chunk_size;
		if ((stat.st_size - stat.st_size / chunk_size * chunk_size) > 0)
			nc++;
		printf("ilosc chunkow [%u]: %u\n", chunk_size, nc);
		
		// wylicz ilosc lisci - bo to nie to samo co ilosc chunkow
		nl = 1 << (order2(nc));
		printf("nc: %u  nl: %u\n", nc, nl);
		
		// alokuj tablice chunkow, ktora pozniej podepniemy pod liscie
		tab_chunk = malloc(nl * sizeof(struct chunk));
		memset(tab_chunk, 0, nl * sizeof(struct chunk));
		
		// inicjalizuj tab chunkow32
		for (x = 0; x < nl; x++) {
			tab_chunk[x].state = CH_EMPTY;
		}

		
		
		// utworz drzewko dla podanego pliku
		root8 = build_tree(tab, nc, &ret);

		
		
		rd = 0;
		c = 0;
		while (rd < stat.st_size) {
			r = read(fd, buf, chunk_size);

			SHA1Reset(&context);
			SHA1Input(&context, buf, r);
			SHA1Result(&context, digest);


			// docelowo wrzucic te aktualizacje do update_chunk()
			tab_chunk[c].state = CH_ACTIVE;
			tab_chunk[c].offset = c * chunk_size;
			tab_chunk[c].len = r;
			memcpy(tab_chunk[c].sha, digest, 20);		//20 - wielkosc tab digest - to chyba bedzie trzeba usunac  - bo sha w nodeach tez jest
			memcpy(ret[2 * c].sha, digest, 20);		//20 - wielkosc tab digest
			ret[2 * c].state = ACTIVE;
			rd += r;
			c++;
		}
		close(fd);

		printf("rd: %u\n", rd);

		
		

		// podlacz tablice chunkow do lisci i inicjalizuj chunki
		// w zasadzie to podpiecie powinna realizowac build_tree()
		for (x = 0; x < nl; x++) {
			ret[x * 2].chunk = &tab_chunk[x];
			tab_chunk[x].node = &ret[x * 2];
		}

		
		// wyswietl drzewko dla podanego pliku
		show_tree_root_based(&ret[root8->number]);

		dump_chunk_tab(tab_chunk, nl);
		
		update_sha(ret, nl);
		dump_tree(ret, nl);	
		
		
		remote_peer.tree = ret;
		remote_peer.nl = nl;
		remote_peer.nc = nc;
		remote_peer.type = SEEDER;
		remote_peer.handshake_req = NULL;
		remote_peer.handshake_req_len = 0;
		remote_peer.handshake_resp = NULL;
		remote_peer.handshake_resp_len = 0;
		// peer->requets NULL, reques_len =0 
		remote_peer.start_chunk = 0;
		remote_peer.end_chunk = nc - 1;
		
		proto_test(&remote_peer);
	} else {
		remote_peer.tree = NULL;
		remote_peer.nl = 0;
		remote_peer.nc = 0;
		remote_peer.type = LEECHER;
		remote_peer.handshake_req = NULL;
		remote_peer.handshake_req_len = 0;
		remote_peer.handshake_resp = NULL;
		remote_peer.handshake_resp_len = 0;
		
		proto_test(&remote_peer);			// 0 - oznacza ze to tryb receivera (klienta)
		
	}

	
	
	//proto_test();

	
	return 0;
}

