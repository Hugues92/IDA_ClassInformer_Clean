
// ****************************************************************************
// File: Vftable.cpp
// Desc: Virtual function table parsing support
//
// ****************************************************************************
#include "stdafx.h"
#include "Core.h"
#include "Vftable.h"
#include "RTTI.h"
#include "pro.h"

namespace vftable
{
	int tryKnownMember(ea_t vft, ea_t eaMember, UINT iIndex, LPCSTR prefixName, ea_t parentvft, ea_t eaJump);
	bool IsDefault(ea_t vft, ea_t eaMember, UINT iIndex, LPCSTR szClassName, LPSTR szCurrName);
	bool hasDefaultComment(ea_t entry, LPSTR cmnt, LPSTR* cmntData);
};

// Attempt to get information of and fix vftable at address
// Return TRUE along with info if valid vftable parsed at address
BOOL vftable::getTableInfo(ea_t ea, vtinfo &info, size_t parentSize)
{
    ZeroMemory(&info, sizeof(vtinfo));
	int motive = 0;

	// Start of a vft should have an xref and a name (auto, or user, etc).
    // Ideal flags 32bit: FF_DWRD, FF_0OFF, FF_REF, FF_NAME, FF_DATA, FF_IVL
    //dumpFlags(ea);
    flags_t flags = get_flags_novalue(ea);
	bool properVFT = TRUE;
	//properVFT = properVFT && hasRef(flags);
	//properVFT = properVFT && has_any_name(flags);
	properVFT = properVFT && (isEa(flags) || isUnknown(flags));

	if(!properVFT)
	{
		msg("\t\t\tUnreferenced vftable: "EAFORMAT": "EAFORMAT"-"EAFORMAT", methods: %d, Motive=%d\n", ea, info.start, info.end, info.methodCount, motive);
		return(FALSE);
	}
	else
    {
        // Get raw (auto-generated mangled, or user named) vft name
        //if (!get_name(BADADDR, ea, info.name, SIZESTR(info.name)))
        //    msg(EAFORMAT" ** vftable::getTableInfo(): failed to get raw name!\n", ea);

        // Determine the vft's method count
        ea_t start = info.start = ea;
		size_t index = 0;
        while (TRUE)
        {
            // Should be an ea_t offset to a function here (could be unknown if dirty IDB)
            // Ideal flags for 32bit: FF_DWRD, FF_0OFF, FF_REF, FF_NAME, FF_DATA, FF_IVL
            //dumpFlags(ea);
            flags_t indexFlags = get_flags_novalue(ea);
            if (!(isEa(indexFlags) || isUnknown(indexFlags)))
            {
                motive = 1;
                break;
            }

            // Look at what this (assumed vftable index) points too
            ea_t memberPtr = getEa(ea);
            if (!(memberPtr && (memberPtr != BADADDR)))
            {
                // vft's often have a zero ea_t (NULL pointer?) following, fix it
                if (memberPtr == 0)
                    fixEa(ea);

                motive = 2;
                break;
            }

            // Should see code for a good vft method here, but it could be dirty
            flags_t flags = get_flags_novalue(memberPtr);
            if (!(isCode(flags) || isUnknown(flags)))
                if (ea == start)
                    do_unknown(memberPtr, DOUNK_SIMPLE);
                else
                {
                    motive = 3;
                    break;
                }

            if (index && (index >= parentSize))	// unless we are still smaller than our parent
            {
                // If we see a ref after first index it's probably the beginning of the next vft or something else
                if (hasRef(indexFlags))
                {
                    motive = 4;
                    break;
                }

                // If we see a COL here it must be the start of another vftable
                if (RTTI::_RTTICompleteObjectLocator::isValid(memberPtr))
                {
                    motive = 5;
                    break;
                }
            }
			else  // Just for debugging
			{
				// If we see a ref at the first index it must be a function pointer
				if (hasRef(indexFlags))
				{
					motive = 4;
				}

				// If we see a COL here it must be the start of another vftable
				if (RTTI::_RTTICompleteObjectLocator::isValid(memberPtr))
				{
					motive = 5;
				}
			}

            // As needed fix ea_t pointer, and, or, missing code and function def here
            fixEa(ea);
            if (!fixFunction(memberPtr))
				break;

            ea += sizeof(ea_t);
			index++;
        };

        // Reached the presumed end of it
        if ((info.methodCount = ((ea - start) / sizeof(ea_t))) > 0)
        {
            info.end = ea;
            //msg(" vftable: "EAFORMAT"-"EAFORMAT", methods: %d\n", rtInfo.eaStart, rtInfo.eaEnd, rtInfo.uMethods);
            return(TRUE);
        }
    }

    if (BADADDR != ea)
        msg("\t\t\tCannot interpret vftable: "EAFORMAT": "EAFORMAT"-"EAFORMAT", methods: %d, Motive=%d\n", ea, info.start, info.end, info.methodCount, motive);
	// dumpFlags(ea);
    return(FALSE);
}


// Get relative jump target address

static ea_t getRelJmpTarget(ea_t eaAddress)
{
	BYTE bt = get_byte(eaAddress);
	if(bt == 0xEB)
	{
		bt = get_byte(eaAddress + 1);
		if(bt & 0x80)
			return(eaAddress + 2 - ((~bt & 0xFF) + 1));
		else
			return(eaAddress + 2 + bt);
	}
	else
	if(bt == 0xE9)
	{
		UINT dw = get_32bit(eaAddress + 1);
		if(dw & 0x80000000)
			return(eaAddress + 5 - (~dw + 1));
		else
			return(eaAddress + 5 + dw);
	}
	else
		return(BADADDR);
}

#define SN_constructor 1
#define SN_destructor  2
#define SN_vdestructor 3
#define SN_scalardtr   4
#define SN_vectordtr   5

bool vftable::IsDefault(ea_t vft, ea_t eaMember, UINT iIndex, LPCSTR szClassName, LPSTR szCurrName)
{

	LPCSTR szBase = szCurrName;
	//msg("  "EAFORMAT" ** Member %s for %s **\n", eaMember, szBase, szClassName);
	while (stristr(szBase, "j_") == szBase)
	{
		//msg("  "EAFORMAT" ** Jumping member %s for %s **\n", eaMember, szBase, szClassName);
		szBase += 2;
	}
	char demangledName[MAXSTR] = "";
	if (getPlainTypeName(szBase, demangledName))
	{
		//msg("  ** from '%s' to '%s'\n", szBase, demangledName);
		szBase = demangledName;
	}

	bool isUnk = false;
	bool isFunc = false;
	bool isPure = false;
	bool isBug = false;
	char sz[MAXSTR];
	strcpy_s(sz, MAXSTR - 1, szBase);
	LPCSTR szi = strstr(sz, "::_");	// Corrects a bug in previous version of Modified
	if (szi && (sz + (strlen(sz) - 3) == szi))
	{
		//msg("  "EAFORMAT" ** Bugged member %s for %s as %s **\n", eaMember, sz, szClassName, szCurrName);
		isBug = true;
	}
	while (LPSTR sep = strstr(sz, "::"))
	{
		sep[0] = '_';
		sep[1] = '_';
	}
	while (LPSTR sep = strstr(sz, ":"))
	{
		sep[0] = '_';
	}
	if (stristr(sz, "_unk"))
	{
		//msg("  "EAFORMAT" ** Unk member %s for %s as %s **\n", eaMember, sz, szClassName, szCurrName);
		isUnk = true;
	}
	if (stristr(sz, "_Func"))
	{
		//msg("  "EAFORMAT" ** Func member %s for %s as %s **\n", eaMember, sz, szClassName, szCurrName);
		isFunc = true;
	}
	if (stristr(sz, "__purecall"))
	{
		//msg("  "EAFORMAT" ** Pure member %s for %s as %s **\n", eaMember, sz, szClassName, szCurrName);
		isPure = true;
	}

	if (isUnk || isFunc || isPure || isBug)
		return true;
	return false;
}

char * get_any_indented_cmt(ea_t entry)
{
	static char szTemp[MAXSTR];
	strcpy_s(szTemp, "");
	if (0 < get_cmt(entry, false, szTemp, MAXSTR - 1))
		return szTemp;
	else
		if (0 < get_cmt(entry, true, szTemp, MAXSTR - 1))
			return szTemp;
		else
			return "";
}

bool vftable::hasDefaultComment(ea_t entry, LPSTR cmnt, LPSTR* cmntData)
{
	flags_t flags = getFlags(entry);
	bool isDefault = false;

	if (has_cmt(flags))
	{
		LPCSTR sz = NULL;
		strcpy_s(cmnt, MAXSTR - 1, get_any_indented_cmt(entry));
		//msg("  "EAFORMAT" ** Comment '%s' **\n", entry, cmnt);
		if (cmntData && strstr(cmnt, " (#Func ") == cmnt)
		{
			sz = strstr(cmnt, "::Func");
			if (sz)
			{
				// ignore those comments
				sz = strchr(cmnt, ')');
				isDefault = true;
			}
			else
			{
				sz = strstr(cmnt, "::purecall");
				if (sz)
				{
					// ignore those comments
					sz = strchr(cmnt, ')');
					isDefault = true;
				}
				else
				{
					sz = strstr(cmnt, "::_");	// Corrects a bug in previous version of Modified
					if (sz && (cmnt + (strlen(cmnt) - 3) == sz) )
					{
						// ignore those comments
						sz = strchr(cmnt, ')');
						isDefault = true;
					}
				}
			}
		//msg("  "EAFORMAT" ** Default comment '%s' [%s] **\n", entry, cmnt, sz);
			*cmntData = strchr(cmnt, ')') + 2;
			return isDefault;
		}
	}
	//else
	//	msg("  "EAFORMAT" ** No comment **\n", entry);
	return false;
}

// Try to identify and place known class member types
int vftable::tryKnownMember(ea_t vft, ea_t eaMember, UINT iIndex, LPCSTR prefixName, ea_t parentvft, ea_t eaJump)
{
	int iType = 0;
	char szClassName[MAXSTR] = "";
	if (strlen(prefixName) > (MAXSTR - 2))
	{
		msgR("  "EAFORMAT" ** Class Name too long!\n", vft);
		return iType;
	}
	strcpy_s(szClassName, MAXSTR - 1, prefixName);

	if (eaMember && (eaMember != BADADDR))
	{
		char szCurrName[MAXSTR] = "";
		LPSTR szTemp = NULL;

		flags_t flags = getFlags((ea_t)eaMember);
		flags_t vftflags = getFlags(vft);

		//msg("%s  "EAFORMAT" ** Processing member %s (%d) at "EAFORMAT" from "EAFORMAT" ["EAFORMAT"] **\n", eaJump != BADADDR ? "\t" : "", eaMember, szNewName, iIndex, vft, parentvft, flags);

		char szCmnt[MAXSTR] = "";
		bool isDefaultCmnt = hasDefaultComment(vft, szCmnt, &szTemp) || (0 == strlen(szCmnt));
		if (isDefaultCmnt)
			set_cmt(vft, "", false);
		//msg("  "EAFORMAT" ** Comment '%s' is default ? %d **\n", eaMember, szCmnt, isDefaultCmnt);

		// Check if it has a default name
		bool isDefault = false;
		if (has_name(flags) && !has_dummy_name(flags))
		{
			qstring q = get_true_name(eaMember);
			strcpy_s(szCurrName, q.c_str());
			isDefault = IsDefault(vft, eaMember, iIndex, szClassName, szCurrName);
		}

		if (isDefault)
		{
			// Should be code
			if (!isCode(flags))
			{
				fixFunction(eaMember);
				flags = getFlags((ea_t)eaMember);
			}
			if (isCode(flags))
			{
				ea_t ea = eaMember;
				ea_t eaAddress = BADADDR;
				while ((eaAddress = getRelJmpTarget(ea)) != BADADDR)
				{
					set_name(ea, "", SN_NOWARN);	// will recalc the j_Name when Name is updated
					set_cmt(ea, "", false);
					ea = eaAddress;
				}

				if (ea != BADADDR)
				{
					set_name(ea, "", SN_NOWARN);
					bool isDefaultCmnt = hasDefaultComment(ea, szCmnt, &szTemp) || (0 == strlen(szCmnt));
					if (isDefaultCmnt)
						set_cmt(ea, "", false);
					//msg("%s ="EAFORMAT" ** Processed member %s (%d) at "EAFORMAT" from "EAFORMAT" ["EAFORMAT"] **\n", eaJump != BADADDR ? "\t" : "", ea, szCurrName, iIndex, vft, parentvft, flags);
				}
			}
			else
				msg(" "EAFORMAT" ** Not code at this member! **\n", eaMember);
		}

		isDefaultCmnt = hasDefaultComment(eaMember, szCmnt, &szTemp) || (0 == strlen(szCmnt));
		if (isDefaultCmnt)
			set_cmt(eaMember, "", false);

		//msg("  "EAFORMAT" ** Done member '%s' at %08X (%s) **\n", eaMember, szNewName, vft, szCmnt);
	}

	return(iType);
}


/*
TODO: On hold for now.
Do we really care about detected ctors and dtors?
Is it helpful vs the problems of naming member functions?
*/


// Process vftable member functions

// TODO: Just try the fix missing function code
void vftable::processMembers(LPCTSTR lpszName, ea_t eaStart, ea_t* eaEnd, LPCTSTR prefixName, ea_t parentvft, UINT parentCount)
{
	ea_t eaAddress = eaStart;
	ea_t eaShorterEnd = BADADDR;
	UINT iIndex = 0;
	UINT iCount = (*eaEnd - eaStart) / sizeof(ea_t);

	//msg(" "EAFORMAT" to "EAFORMAT" as '%s' for %d from "EAFORMAT" : %d\n", eaStart, *eaEnd, lpszName, iCount, parentvft, parentCount);

	while (eaAddress < *eaEnd)
	{
		ea_t eaMember;
		if (getVerify_t(eaAddress, eaMember))
		{
			// Missing/bad code?
			if(!get_func(eaMember))
			{
				//msg(" "EAFORMAT" ** No member function here! Start:"EAFORMAT" End:"EAFORMAT" as '%s' %d of %d Parent: ["EAFORMAT" : %d] **\n", eaMember, eaStart, *eaEnd, lpszName, iIndex, iCount, parentvft, parentCount);
				if (BADADDR == eaShorterEnd)
					eaShorterEnd = eaAddress;
				//fixFunction(eaMember);
			}
			else
			{
				tryKnownMember(eaAddress, eaMember, iIndex++, prefixName, (iIndex < parentCount) ? parentvft : BADADDR, BADADDR);
				eaShorterEnd = BADADDR;
			}
		}
		else
			msg(" "EAFORMAT" ** Failed to read member pointer! **\n", eaAddress);

		eaAddress += sizeof(ea_t);
	};
	if (BADADDR != eaShorterEnd) {
		*eaEnd = eaShorterEnd;
		//msg(" "EAFORMAT" ** Shortened! **\n", eaShorterEnd);
	}
}

ea_t vftable::getMemberName(LPSTR name, ea_t eaAddress)
{
	ea_t eaMember = BADADDR;
	bool found = false;
	char szTemp[MAXSTR] = "";
	strcpy_s(name, MAXSTR - 1, "");
	//msg("  "EAFORMAT" GetMemberName:'%s' "EAFORMAT"\n", eaMember, name, eaAddress);
	if (getVerify_t(eaAddress, eaMember))
	{
		// Missing/bad code?
		if (!get_func(eaMember))
			fixFunction(eaMember);
		if (!get_func(eaMember))
		{
			msg(" "EAFORMAT" ** No member function here! **\n", eaMember);
			eaMember = BADADDR;
			return eaMember;
		}

		// E9 xx xx xx xx   jmp   xxxxxxx
		BYTE Byte = get_byte(eaMember);
		if ((Byte == 0xE9) || (Byte == 0xEB))
		{
			//msg(" !"EAFORMAT" GetMemberName:'%s' "EAFORMAT"\n", eaMember, name, eaAddress);
			eaAddress = eaMember;
		}
		flags_t flags = getFlags(eaAddress);
		if (has_cmt(flags))
		{
			get_cmt(eaAddress, false, szTemp, MAXSTR - 1);
			if (szTemp == strstr(szTemp, " (#Func "))
			{
				char * szResult = strchr(szTemp, ')') + 2;
				strcpy_s(name, MAXSTR - 1, szResult);
				found = true;
				//msg(" *"EAFORMAT" GetMemberName:'%s' "EAFORMAT" %d\n", eaMember, name, eaAddress, flags);
			}
		}
		if (!found)
		{
			qstring cn = get_true_name(eaMember);
			if (cn.c_str())
				strncpy(szTemp, cn.c_str(), (MAXSTR - 1));
			strcpy_s(name, MAXSTR - 1, szTemp);
		}
	}
	else
	{
		msg(" "EAFORMAT" ** Failed to read member pointer! **\n", eaAddress);
		eaMember = BADADDR;
	}
	//msg(" ="EAFORMAT" GetMemberName:'%s' "EAFORMAT"\n", eaMember, name, eaAddress);
	return eaMember;
}

ea_t vftable::getMemberShortName(LPSTR name, ea_t eaAddress)
{
	bool found = false;
	char szTemp[MAXSTR] = "";
	ea_t eaMember = getMemberName(szTemp, eaAddress);
	LPCSTR sz = strstr(szTemp, "::");
	if (sz)
		strcpy_s(name, MAXSTR - 1, sz + 3);
	else
		strcpy_s(name, MAXSTR - 1, "");
	return eaMember;
}