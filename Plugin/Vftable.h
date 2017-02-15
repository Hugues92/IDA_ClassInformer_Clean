
// ****************************************************************************
// File: Vftable.h
// Desc: Virtual function table parsing support
//
// ****************************************************************************
#pragma once

namespace vftable
{
	// vftable info container
	struct vtinfo
	{
		ea_t start, end;
		int  methodCount;
		//char name[MAXSTR];
	};

	BOOL getTableInfo(ea_t ea, vtinfo &info, size_t parentSize);

	// Returns TRUE if mangled name indicates a vftable
	inline BOOL isValid(LPCSTR name){ return(*((PDWORD) name) == 0x375F3F3F /*"??_7"*/); }

	// Identify and name common member functions
	void processMembers(LPCTSTR name, ea_t eaStart, ea_t* eaEnd, LPCSTR prefixName, ea_t parentvft, UINT parentCount);
	bool IsClass(LPCSTR szClassName, LPSTR szCurrName, bool translate);
	ea_t getMemberName(LPSTR name, ea_t eaAddress);
	ea_t getMemberShortName(LPSTR name, ea_t eaAddress);

	typedef std::string String;
}
