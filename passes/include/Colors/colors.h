#ifndef _COLORS_
#define _COLORS_

/* FOREGROUND */
#define RST  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"
#define KBLD  "\x1B[1m"
#define KUND  "\x1B[4m"

#define RED(x) KRED x RST
#define GREEN(x) KGRN x RST
#define YELLOW(x) KYEL x RST
#define BLUE(x) KBLU x RST
#define MAGENTA(x) KMAG x RST
#define CYAN(x) KCYN x RST
#define WHITE(x) KWHT x RST

#define SRED(x) KRED << x << RST
#define SGREEN(x) KGRN << x << RST
#define SYELLOW(x) KYEL << x << RST
#define SBLUE(x) KBLU << x << RST
#define SMAGENTA(x) KMAG << x << RST
#define SCYAN(x) KCYN << x << RST
#define SWHITE(x) KWHT << x << RST

#define BOLD(x)	KBLD x RST
#define UNDERLINE(x)	KUND x RST

#define SBOLD(x)	KBLD << x << RST
#define SUNDERLINE(x)	KUND << x << RST

#define PBOLD(x)	KBLD + x + RST
#define PUNDERLINE(x)	KUND + x + RST


#endif	/* _COLORS_ */