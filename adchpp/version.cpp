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

#include "adchpp.h"
#include "version.h"

#ifndef ADCHPP_REVISION
#define ADCHPP_REVISION 0
#endif

#define xstrver(s) strver(s)
#define strver(s) #s

// Version numbers follow Semantic Versioning 2.0.0 <https://semver.org>.

// don't forget to also update the .rc file of adchppd!
#define APPNAME "ADCH++"
#define VERSIONSTRING "3.0.2 (r\"" xstrver(ADCHPP_REVISION) "\")"
#define VERSIONFLOAT 3.02

#ifndef NDEBUG
#define BUILDSTRING "Debug"
#else
#define BUILDSTRING "Release"
#endif

#define FULLVERSIONSTRING VERSIONSTRING " " BUILDSTRING

namespace adchpp {

using namespace std;

string appName = APPNAME;
string versionString = FULLVERSIONSTRING;
float versionFloat = VERSIONFLOAT;

}
