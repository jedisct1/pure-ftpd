#ifndef __MESSAGES_H__
#define __MESSAGES_H__ 1

#ifdef MESSAGES_DE
# define MESSAGES_LOCALE "de_DE"
# include "messages_de.h"

#elif defined(MESSAGES_RO)
# define MESSAGES_LOCALE "ro_RO"
# include "messages_ro.h"

#elif defined(MESSAGES_FR)
# define MESSAGES_LOCALE "fr_FR"
# include "messages_fr.h"

#elif defined(MESSAGES_PL)
# define MESSAGES_LOCALE "pl_PL"
# include "messages_pl.h"

#elif defined(MESSAGES_ES)
# define MESSAGES_LOCALE "es_ES"
# include "messages_es.h"

#elif defined(MESSAGES_DA)
# define MESSAGES_LOCALE "da_DK"
# include "messages_da.h"

#elif defined(MESSAGES_NL)
# define MESSAGES_LOCALE "nl_NL"
# include "messages_nl.h"

#elif defined(MESSAGES_IT)
# define MESSAGES_LOCALE "it_IT"
# include "messages_it.h"

#elif defined(MESSAGES_PT_BR)
# define MESSAGES_LOCALE "pt_BR"
# include "messages_pt_br.h"

#elif defined(MESSAGES_SK)
# define MESSAGES_LOCALE "sk_SK"
# include "messages_sk.h"

#elif defined(MESSAGES_KR)
# define MESSAGES_LOCALE "ko_KO"
# include "messages_kr.h"

#elif defined(MESSAGES_FR_FUNNY)
# define MESSAGES_LOCALE "fr_FR"
# include "messages_fr_funny.h"

#elif defined(MESSAGES_SV)
# define MESSAGES_LOCALE "sv_SE"
# include "messages_sv.h"

#elif defined(MESSAGES_NO)
# define MESSAGES_LOCALE "no_NO"
# include "messages_no.h"

#elif defined(MESSAGES_RU)
# define MESSAGES_LOCALE "ru_RU"
# include "messages_ru.h"

#elif defined(MESSAGES_ZH_CN)
# define MESSAGES_LOCALE "zh_CN"
# include "messages_zh_cn.h"

#elif defined(MESSAGES_ZH_TW)
# define MESSAGES_LOCALE "zh_TW"
# include "messages_zh_tw.h"

#elif defined(MESSAGES_CS_CZ)
# define MESSAGES_LOCALE "cs_CZ"
# include "messages_cs_cz.h"

#elif defined(MESSAGES_TR)
# define MESSAGES_LOCALE "tr_TR"
# include "messages_tr.h"

#elif defined(MESSAGES_HU)
# define MESSAGES_LOCALE "hu_HU"
# include "messages_hu.h"

#elif defined(MESSAGES_CA_ES)
# define MESSAGES_LOCALE "ca_ES"
# include "messages_ca_es.h"

#else
# define MESSAGES_LOCALE "en_GB"
# include "messages_en.h"
# ifndef MESSAGES_EN
#  define MESSAGES_EN 1
# endif
#endif

/* Favor paranoia over help for sysadmin */
#ifdef PARANOID_MESSAGES
# undef MSG_NOTRUST
# define MSG_NOTRUST MSG_AUTH_FAILED
#endif

#endif
