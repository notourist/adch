/*
 * Copyright (C) 2006-2023 Jacek Sieka, arnetheduck on gmail point com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef ADCHPP_ADCHPP_CONFIG_H_
#define ADCHPP_ADCHPP_CONFIG_H_

#ifndef _REENTRANT
# define _REENTRANT 1
#endif

#ifdef _MSC_VER
//disable the deprecated warnings for the CRT functions.
# define _CRT_SECURE_NO_DEPRECATE 1
# define _ATL_SECURE_NO_DEPRECATE 1
# define _CRT_NON_CONFORMING_SWPRINTFS 1
#endif

#if defined(_MSC_VER) || defined(__MINGW32__)
# define _LL(x) x##ll
# define _ULL(x) x##ull
# define I64_FMT "%I64d"
#elif defined(SIZEOF_LONG) && SIZEOF_LONG == 8
# define _LL(x) x##l
# define _ULL(x) x##ul
# define I64_FMT "%ld"
#else
# define _LL(x) x##ll
# define _ULL(x) x##ull
# define I64_FMT "%lld"
#endif

#ifdef _WIN32
#define PATH_SEPARATOR '\\'
#define PATH_SEPARATOR_STR "\\"
#else
#define PATH_SEPARATOR '/'
#define PATH_SEPARATOR_STR "/"
#endif

#ifdef _WIN32

# ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0501
# endif
# ifndef _WIN32_IE
#  define _WIN32_IE 0x0501
# endif
# ifndef WINVER
#  define WINVER 0x0501
# endif
# ifndef STRICT
#  define STRICT 1
# endif
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN 1
# endif
# ifndef NOMINMAX
# define NOMINMAX
# endif

# define ADCHPP_VISIBLE
# ifdef BUILDING_ADCHPP
#  define ADCHPP_DLL __declspec(dllexport)
# else
#  define ADCHPP_DLL __declspec(dllimport)
# endif // DLLEXPORT

#else

# define ADCHPP_DLL __attribute__ ((visibility("default")))
# define ADCHPP_VISIBLE __attribute__ ((visibility("default")))

#endif


#endif /* CONFIG_H_ */
