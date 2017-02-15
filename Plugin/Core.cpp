
// ****************************************************************************
// File: Core.cpp
// Desc: Class Informer
//
// ****************************************************************************
#include "stdafx.h"
#include "Core.h"
#include "Vftable.h"
#include "RTTI.h"
#include "MainDialog.h"
#include <map>
//
#include <WaitBoxEx.h>
#include <IdaOgg.h>

typedef std::map<ea_t, std::string> STRMAP;

// Netnode constants
const static char NETNODE_NAME[] = {"$ClassInformer_node"};
const char NN_DATA_TAG  = 'A';
const char NN_TABLE_TAG = 'S';

// Our netnode value indexes
enum NETINDX
{
    NIDX_VERSION,   // ClassInformer version
    NIDX_COUNT      // Table entry count
};

// VFTable entry container (fits in a netnode MAXSPECSIZE size)
#pragma pack(push, 1)
struct TBLENTRY
{
    ea_t vft;
	WORD methods;
    WORD flags;
    WORD strSize;
	char str[MAXSPECSIZE - (sizeof(ea_t) + (sizeof(WORD) * 3))]; // IDA MAXSTR = 1024
};
#pragma pack(pop)

// Line background color for non parent/top level hierarchy lines
// TOOD: Assumes text background is white. A way to make these user theme/style color aware?
#define GRAY(v) RGB(v,v,v)
static const bgcolor_t NOT_PARENT_COLOR = GRAY(235);

// === Function Prototypes ===
static BOOL processStaticTables();
static void showEndStats();
static BOOL getRttiData();

// === Data ===
static TIMESTAMP s_startTime = 0;
static HMODULE myModuleHandle = NULL;
static UINT staticCCtorCnt = 0, staticCppCtorCnt = 0, staticCDtorCnt = 0;
static UINT startingFuncCount = 0, staticCtorDtorCnt = 0;
static BOOL uiHookInstalled = FALSE;
static int  chooserIcon = 0;
static netnode *netNode = NULL;
static eaList colList;

// Options
BOOL optionPlaceStructs      = TRUE;
BOOL optionProcessStatic     = TRUE;
BOOL optionOverwriteComments = FALSE;
BOOL optionAudioOnDone       = TRUE;

// List box defs
static const char LBTITLE[] = {"[Class Informer]"};
static const UINT LBCOLUMNCOUNT = 5;
static const int listBColumnWidth[LBCOLUMNCOUNT] = { (8 | CHCOL_HEX), (4 | CHCOL_DEC), 3, 19, 500 };
static const LPCSTR columnHeader[LBCOLUMNCOUNT] =
{
	"Vftable",
	"Methods",
    "Flags",
    "Type",
	"Hierarchy"
};

static int idaapi uiCallback(PVOID obj, int eventID, va_list va);
static void freeWorkingData()
{
    try
    {
        if (uiHookInstalled)
        {
            uiHookInstalled = FALSE;
            unhook_from_notification_point(HT_UI, uiCallback, myModuleHandle);
        }

        if (chooserIcon)
        {
            free_custom_icon(chooserIcon);
            chooserIcon = 0;
        }

        RTTI::freeWorkingData();
        colList.clear();

        if (netNode)
        {
            delete netNode;
            netNode = NULL;
        }
    }
    CATCH()
}

// Initialize
void CORE_Init()
{
    GetModuleHandleEx((GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS), (LPCTSTR)&CORE_Init, &myModuleHandle);
}

// Uninitialize
// Normally doesn't happen as we need to stay resident for the modal windows
void CORE_Exit()
{
    try
    {
        OggPlay::endPlay();
        freeWorkingData();
    }
    CATCH()
}


// Init new netnode storage
static void newNetnodeStore()
{
    // Kill any existing store data first
    netNode->supdel_all(NN_DATA_TAG);
    netNode->supdel_all(NN_TABLE_TAG);

    // Init defaults
    netNode->altset_idx8(NIDX_VERSION, MY_VERSION, NN_DATA_TAG);
    netNode->altset_idx8(NIDX_COUNT,   0,          NN_DATA_TAG);
}

static WORD getStoreVersion(){ return((WORD)netNode->altval_idx8(NIDX_VERSION, NN_DATA_TAG)); }
static UINT getTableCount(){ return(netNode->altval_idx8(NIDX_COUNT, NN_DATA_TAG)); }
static BOOL setTableCount(UINT count){ return(netNode->altset_idx8(NIDX_COUNT, count, NN_DATA_TAG)); }
static BOOL getTableEntry(TBLENTRY &entry, UINT index){ return(netNode->supval(index, &entry, sizeof(TBLENTRY), NN_TABLE_TAG) > 0); }
static BOOL setTableEntry(TBLENTRY &entry, UINT index){ return(netNode->supset(index, &entry, (offsetof(TBLENTRY, str) + entry.strSize), NN_TABLE_TAG)); }

static UINT CALLBACK lw_onGetLineCount(PVOID obj){ return(getTableCount()); }
static void CALLBACK lw_onMakeLine(PVOID obj, UINT n, char * const *cell)
{
    #ifdef __EA64__
    static char addressFormat[16];
    #endif

	if(n == 0)
	{
        // Set headers
		for(UINT i = 0; i < LBCOLUMNCOUNT; i++)
			strcpy(cell[i], columnHeader[i]);

        // vft hex address format
        #ifdef __EA64__
        UINT count = getTableCount();
        int maxDigits = 0;
        char buffer[32];
        for (UINT i = 0; i < count; i++)
        {
            TBLENTRY e; e.vft = 0;
            getTableEntry(e, i);
            int digits = strlen(_ui64toa(e.vft, buffer, 16));
            if (digits > maxDigits) maxDigits = digits;
        }
        if (++maxDigits > 16) maxDigits = 16;
        sprintf(addressFormat, "%%0%uI64X", maxDigits);
        #endif
	}
	else
	{
        // Populate requested row
        TBLENTRY e;
        getTableEntry(e, (n - 1));
        // vft address
        #ifdef __EA64__
        sprintf(cell[0], addressFormat, e.vft);
        #else
        sprintf(cell[0], EAFORMAT, e.vft);
        #endif
        // Method count
        if (e.methods > 0)
            sprintf(cell[1], "%u", e.methods); // "%04u"
        else
            strcpy(cell[1], "???");
        // Flags
        char flags[4];
        int pos = 0;
        if (e.flags & RTTI::CHD_MULTINH)   flags[pos++] = 'M';
        if (e.flags & RTTI::CHD_VIRTINH)   flags[pos++] = 'V';
        if (e.flags & RTTI::CHD_AMBIGUOUS) flags[pos++] = 'A';
        flags[pos++] = 0;
        memcpy(cell[2], flags, pos);
        // Type
        LPCSTR tag = strchr(e.str, '@');
        if (tag)
        {
            pos = (tag - e.str);
            memcpy(cell[3], e.str, pos);
            cell[3][pos] = 0;
            ++tag;
        }
        else
        {
            // Can happen when string is MAXSTR and greater
            //_ASSERT(FALSE);
            strcpy(cell[3], "??** MAXSTR overflow!");
            tag = e.str;
            pos = (strlen(e.str) + 1);
        }
        // Composition/hierarchy
        strncpy(cell[4], tag, (MAXSTR - 1));
	}
}

static int CALLBACK lw_onGetIcon(PVOID obj, UINT n)
{
    //return(n);
	if(n == 0)
	    return(0);
	else
    {
        /*
        TBLENTRY e;
        getTableEntry(e, (n - 1));
        return((e.flags & RTTI::IS_TOP_LEVEL) ? 77 : 191);
        */
        return(191);
    }
}

static void CALLBACK lw_onSelect(PVOID obj, UINT n)
{
    TBLENTRY e;
    getTableEntry(e, (n - 1));
    jumpto(e.vft);
}
static void CALLBACK lw_onClose(PVOID obj) { freeWorkingData(); }

// Add an entry to the vftable list
void addTableEntry(UINT flags, ea_t vft, int methodCount, LPCTSTR format, ...)
{
    TBLENTRY e;
    e.vft     = vft;
    e.methods = methodCount;
    e.flags   = flags;
    e.str[SIZESTR(e.str)] = 0;

	va_list vl;
	va_start(vl, format);
	_vsntprintf(e.str, SIZESTR(e.str), format, vl);
	va_end(vl);
    e.strSize = (strlen(e.str) + 1);

    UINT count = getTableCount();
    setTableEntry(e, count);
    setTableCount(++count);
}

static QWidget *findChildWidget(QWidgetList &wl, LPCSTR className)
{
    foreach(QWidget *w, wl)
        if (strcmp(w->metaObject()->className(), className) == 0)
            return(w);
    return(NULL);
}



// Find widget by title text
// If IDs are constant can use "static QWidget *QWidget::find(WId);"?
void customizeChooseWindow()
{
    try
    {
        // Get parent chooser dock widget
        QWidgetList pl = QApplication::activeWindow()->findChildren<QWidget*>("[Class Informer]");
        if (QWidget *dw = findChildWidget(pl, "IDADockWidget"))
        {
            QFile file(STYLE_PATH"view-style.qss");
            if (file.open(QFile::ReadOnly | QFile::Text))
                dw->setStyleSheet(QTextStream(&file).readAll());
        }
        else
            msg("** customizeChooseWindow(): \"IDADockWidget\" not found!\n");

        // Get chooser widget
        if (QTableView *tv = (QTableView *) findChildWidget(pl, "TChooserView"))
        {
            // Set sort by type name
            tv->sortByColumn(3, Qt::DescendingOrder);

            // Resize to contents
            tv->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
            tv->resizeColumnsToContents();
			tv->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);

            UINT count = getTableCount();
            for (UINT row = 0; row < count; row++)
                tv->setRowHeight(row, 24);
        }
        else
            msg("** customizeChooseWindow(): \"TChooserView\" not found!\n");
    }
    CATCH()
}

// UI callback to handle chooser window coloring
static int idaapi uiCallback(PVOID obj, int eventID, va_list va)
{
    if (eventID == ui_get_chooser_item_attrs)
    {
        // ** Stack vars, keep in order
        void *chooserObj = va_arg(va, PVOID);  // 0
        UINT n = va_arg(va, UINT);             // 1
        chooser_item_attrs_t *itemAttrubutes = va_arg(va, chooser_item_attrs_t *); // 2

        // My chooser?
        if (obj == myModuleHandle)
        {
            if (itemAttrubutes)
            {
                TBLENTRY e;
                if (getTableEntry(e, (n - 1)))
                {
                    // Indicate entry is not a top/parent level
                    if (!(e.flags & RTTI::IS_TOP_LEVEL))
                        itemAttrubutes->color = NOT_PARENT_COLOR;
                }
            }
        }
    }
    return(0);
}


static HWND WINAPI getIdaHwnd(){ return((HWND)callui(ui_get_hwnd).vptr); }

void CORE_Process(int arg)
{
    try
    {
        char version[16];
        sprintf(version, "%u.%u", HIBYTE(MY_VERSION), LOBYTE(MY_VERSION));
        msg("\n>> Class Informer: v: %s, built: %s, By Sirmabus\n", version, __DATE__);
        refreshUI();
	    if(!autoIsOk())
	    {
		    msg("** Class Informer: Must wait for IDA to finish processing before starting plug-in! **\n*** Aborted ***\n\n");
		    return;
	    }

        OggPlay::endPlay();
        freeWorkingData();
	    optionAudioOnDone		= TRUE;
	    optionProcessStatic     = TRUE;
	    optionOverwriteComments	= FALSE;
	    optionPlaceStructs		= TRUE;
        startingFuncCount       = get_func_qty();
        staticCppCtorCnt = staticCCtorCnt = staticCtorDtorCnt = staticCDtorCnt = 0;

        // Create storage netnode
        if(!(netNode = new netnode(NETNODE_NAME, SIZESTR(NETNODE_NAME), TRUE)))
        {
            QASSERT(66, FALSE);
            return;
        }

        UINT tableCount     = getTableCount();
        WORD storageVersion = getStoreVersion();
        BOOL storageExists  = ((storageVersion == MY_VERSION) && (tableCount > 0));

        // Ask if we should use storage or process again
        if(storageExists)
            storageExists = (askyn_c(1, "TITLE Class Informer \nHIDECANCEL\nUse previously stored result?        ") == 1);
        else
        if((storageVersion != MY_VERSION) && (tableCount > 0))
            msg("* Storage version mismatch, must rescan *\n");
        refreshUI();

        BOOL aborted = FALSE;
        if(!storageExists)
        {
            newNetnodeStore();

            // Only MS Visual C++ targets are supported
            comp_t cmp = get_comp(default_compiler());
            if (cmp != COMP_MS)
	        {
                msg("** IDA reports target compiler: \"%s\"\n", get_compiler_name(cmp));
                refreshUI();
                int iResult = askbuttons_c(NULL, NULL, NULL, 0, "TITLE Class Informer\nHIDECANCEL\nIDA reports this IDB's compiler as: \"%s\" \n\nThis plug-in only understands MS Visual C++ targets.\nRunning it on other targets (like Borland© compiled, etc.) will have unpredicted results.   \n\nDo you want to continue anyhow?", get_compiler_name(cmp));
                if (iResult != 1)
                {
                    msg("- Aborted -\n\n");
                    return;
                }
	        }

            msg("Working..\n");
            refreshUI();
            WaitBox::show("Class Informer", "Please wait..", "url("STYLE_PATH"progress-style.qss)", ":/classinf/icon.png");
            WaitBox::updateAndCancelCheck(-1);
            s_startTime = getTimeStamp();

            // Add structure definitions to IDA once per session
            static BOOL createStructsOnce = FALSE;
            if (optionPlaceStructs && !createStructsOnce)
            {
                createStructsOnce = TRUE;
                RTTI::addDefinitionsToIda();
            }

            if (!aborted)
            {
                // Get RTTI data
                if (!(aborted = getRttiData()))
                {
                    // Optionally play completion sound
                    if (optionAudioOnDone)
                    {
                        TIMESTAMP endTime = (getTimeStamp() - s_startTime);
                        if (endTime > (TIMESTAMP) 2.4)
                        {
                            OggPlay::endPlay();
                            QFile file(":/classinf/completed.ogg");
                            if (file.open(QFile::ReadOnly))
                            {
                                QByteArray ba = file.readAll();
                                OggPlay::playFromMemory((const PVOID)ba.constData(), ba.size(), TRUE);
                            }
                        }
                    }

                    showEndStats();
                    if (!autoIsOk())
                    {
                        msg("IDA updating, please wait..\n");
                        refreshUI();
                        autoWait();
                    }
                    msg("Done.\n\n");
                }
            }

            refresh_idaview_anyway();
            WaitBox::hide();
            if (aborted)
            {
                msg("- Aborted -\n\n");
                return;
            }
        }
    }
    CATCH()
}

// Print out end stats
static void showEndStats()
{
    try
    {
        msg(" \n\n");
        msg("=========== Stats ===========\n");
        msg("  RTTI vftables: %u\n", getTableCount());
        msg("Functions fixed: %u\n", (get_func_qty() - startingFuncCount));
        msg("Processing time: %s\n", timeString(getTimeStamp() - s_startTime));
    }
    CATCH()
}


// ================================================================================================

// Return TRUE if address as a anterior comment
inline BOOL hasAnteriorComment(ea_t ea)
{
    return(get_first_free_extra_cmtidx(ea, E_PREV) != E_PREV);
}

// Delete any anterior comment(s) at address if there is some
inline void killAnteriorComments(ea_t ea)
{
    delete_extra_cmts(ea, E_PREV);
}

// Force a memory location to be DWORD size
void fixDword(ea_t ea)
{
    if (!isDwrd(get_flags_novalue(ea)))
    {
        setUnknown(ea, sizeof(DWORD));
        doDwrd(ea, sizeof(DWORD));
    }
}

// Force memory location to be ea_t size
void fixEa(ea_t ea)
{
    #ifndef __EA64__
    if (!isDwrd(get_flags_novalue(ea)))
    #else
    if (!isQwrd(get_flags_novalue(ea)))
    #endif
    {
        setUnknown(ea, sizeof(ea_t));
        #ifndef __EA64__
        doDwrd(ea, sizeof(ea_t));
        #else
        doQwrd(ea, sizeof(ea_t));
        #endif
    }
}

// Make address a function
bool fixFunction(ea_t ea)
{
    flags_t flags = get_flags_novalue(ea);
    if (!isCode(flags))
    {
        create_insn(ea);
		if (!isCode(flags))
			return FALSE;
		else
			add_func(ea, BADADDR);
    }
    else
    if (!isFunc(flags))
        add_func(ea, BADADDR);
	return TRUE;
}

// Get IDA EA bit value with verification
BOOL getVerifyEa(ea_t ea, ea_t &rValue)
{
    // Location valid?
    if (isLoaded(ea))
    {
        // Get ea_t value
        rValue = getEa(ea);
        return(TRUE);
    }

    return(FALSE);
}


// Undecorate to minimal class name
// typeid(T).name()
// http://en.wikipedia.org/wiki/Name_mangling
// http://en.wikipedia.org/wiki/Visual_C%2B%2B_name_mangling
// http://www.agner.org/optimize/calling_conventions.pdf

BOOL getPlainTypeName(__in LPCSTR mangled, __out_bcount(MAXSTR) LPSTR outStr)
{
    outStr[0] = outStr[MAXSTR - 1] = 0;

    // Use CRT function for type names
    if (mangled[0] == '.')
    {
        __unDName(outStr, mangled + 1, MAXSTR, malloc, free, (UNDNAME_32_BIT_DECODE | UNDNAME_TYPE_ONLY | UNDNAME_NO_ECSU));
        if ((outStr[0] == 0) || (strcmp((mangled + 1), outStr) == 0))
        {
            msgR("** getPlainClassName:__unDName() failed to unmangle! input: \"%s\"\n", mangled);
            return(FALSE);
        }
    }
    else
    // IDA demangler for everything else
    {
        qstring s;
        int result = demangle_name2(&s, mangled, (MT_MSCOMP | MNG_NODEFINIT));
        if (result < 0)
        {
            //msg("** getPlainClassName:demangle_name() failed to unmangle! result: %d, input: \"%s\"\n", result, mangled);
            return(FALSE);
        }
        else
             strncpy(outStr, s.c_str(), (MAXSTR - 1));

        // No inhibit flags will drop this
        if (LPSTR ending = strstr(outStr, "::`vftable'"))
            *ending = 0;
    }

    return(TRUE);
}

// Wrapper for 'add_struc_member()' with error messages
// See to make more sense of types: http://idapython.googlecode.com/svn-history/r116/trunk/python/idc.py
int addStrucMember(struc_t *sptr, char *name, ea_t offset, flags_t flag, opinfo_t *type, asize_t nbytes)
{
	int r = add_struc_member(sptr, name, offset, flag, type, nbytes);
	switch(r)
	{
		case STRUC_ERROR_MEMBER_NAME:
		msg("AddStrucMember(): error: already has member with this name (bad name)\n");
		break;

		case STRUC_ERROR_MEMBER_OFFSET:
		msg("AddStrucMember(): error: already has member at this offset\n");
		break;

		case STRUC_ERROR_MEMBER_SIZE:
		msg("AddStrucMember(): error: bad number of bytes or bad sizeof(type)\n");
		break;

		case STRUC_ERROR_MEMBER_TINFO:
		msg("AddStrucMember(): error: bad typeid parameter\n");
		break;

		case STRUC_ERROR_MEMBER_STRUCT:
		msg("AddStrucMember(): error: bad struct id (the 1st argument)\n");
		break;

		case STRUC_ERROR_MEMBER_UNIVAR:
		msg("AddStrucMember(): error: unions can't have variable sized members\n");
		break;

		case STRUC_ERROR_MEMBER_VARLAST:
		msg("AddStrucMember(): error: variable sized member should be the last member in the structure\n");
		break;

		case STRUC_ERROR_MEMBER_NESTED:
		msg("AddStrucMember(): error: recursive structure nesting is forbidden\n");
		break;
	};

	return(r);
}


void setUnknown(ea_t ea, int size)
{
    // TODO: Does the overrun problem still exist?
    //do_unknown_range(ea, (size_t)size, DOUNK_SIMPLE);
    while (size > 0)
    {
        int isize = get_item_size(ea);
        if (isize > size)
            break;
        else
        {
            do_unknown(ea, DOUNK_SIMPLE);
            ea += (ea_t)isize, size -= isize;
        }
    };
}


// Scan segment for COLs
static BOOL scanSeg4Cols(segment_t *seg)
{
    char name[64];
    if (get_true_segm_name(seg, name, SIZESTR(name)) <= 0)
        strcpy(name, "???");
    msgR(" N: \"%s\", A: "EAFORMAT" - "EAFORMAT", S: %s.\n", name, seg->startEA, seg->endEA, byteSizeString(seg->size()));

    UINT found = 0;
    if (seg->size() >= sizeof(RTTI::_RTTICompleteObjectLocator))
    {
        ea_t startEA = ((seg->startEA + sizeof(UINT)) & ~((ea_t)(sizeof(UINT) - 1)));
        ea_t endEA   = (seg->endEA - sizeof(RTTI::_RTTICompleteObjectLocator));

        for (ea_t ptr = startEA; ptr < endEA;)
        {
            #ifdef __EA64__
            // Check for possible COL here
            // Signature will be one
            // TODO: Is this always 1 or can it be zero like 32bit?
            if (get_32bit(ptr + offsetof(RTTI::_RTTICompleteObjectLocator, signature)) == 1)
            {
                if (RTTI::_RTTICompleteObjectLocator::isValid(ptr))
                {
                    // yes
                    colList.push_front(ptr);
                    RTTI::_RTTICompleteObjectLocator::doStruct(ptr);
                    ptr += sizeof(RTTI::_RTTICompleteObjectLocator);
                    continue;
                }
            }
            else
            {
                // TODO: Should we check stray BCDs?
                // Each value would have to be tested for a valid type_def and
                // the pattern is pretty ambiguous.
            }
            #else
            // TypeDescriptor address here?
            ea_t ea = getEa(ptr);
            if (ea >= 0x10000)
            {
                if (RTTI::type_info::isValid(ea))
                {
                    // yes, a COL here?
                    ea_t col = (ptr - offsetof(RTTI::_RTTICompleteObjectLocator, typeDescriptor));
                    if (RTTI::_RTTICompleteObjectLocator::isValid2(col))
                    {
                        // yes
                        colList.push_front(col);
                        RTTI::_RTTICompleteObjectLocator::doStruct(col);
                        ptr += sizeof(RTTI::_RTTICompleteObjectLocator);
                        continue;
                    }
                    /*
                    else
                    // No, is it a BCD then?
                    if (RTTI::_RTTIBaseClassDescriptor::isValid2(ptr))
                    {
                        // yes
                        char dontCare[MAXSTR];
                        RTTI::_RTTIBaseClassDescriptor::doStruct(ptr, dontCare);
                    }
                    */
                }
            }
            #endif

            if (WaitBox::isUpdateTime())
                if (WaitBox::updateAndCancelCheck())
                    return(TRUE);

            ptr += sizeof(UINT);
        }
    }

    if (found)
    {
        char numBuffer[32];
        msgR(" Count: %s\n", prettyNumberString(found, numBuffer));
    }
    return(FALSE);
}

// Locate COL by descriptor list
static BOOL findCols()
{
    try
    {
        #ifdef _DEVMODE
        TIMESTAMP startTime = getTimeStamp();
        #endif

        // Usually in ".rdata" seg, try it first
        stdext::hash_set<segment_t *> segSet;
        if (segment_t *seg = get_segm_by_name(".rdata"))
        {
            segSet.insert(seg);
            if (scanSeg4Cols(seg))
                return(FALSE);
        }

        // And ones named ".data"
        int segCount = get_segm_qty();
        //if (colList.empty())
        {
            for (int i = 0; i < segCount; i++)
            {
                if (segment_t *seg = getnseg(i))
                {
                    if (seg->type == SEG_DATA)
                    {
                        if (segSet.find(seg) == segSet.end())
                        {
                            char name[8];
                            if (get_true_segm_name(seg, name, SIZESTR(name)) == SIZESTR(".data"))
                            {
                                if (strcmp(name, ".data") == 0)
                                {
                                    segSet.insert(seg);
                                    if (scanSeg4Cols(seg))
                                        return(FALSE);
                                }
                            }
                        }
                    }
                }
            }
        }

        // If still none found, try any remaining data type segments
        if (colList.empty())
        {
            for (int i = 0; i < segCount; i++)
            {
                if (segment_t *seg = getnseg(i))
                {
                    if (seg->type == SEG_DATA)
                    {
                        if (segSet.find(seg) == segSet.end())
                        {
                            segSet.insert(seg);
                            if (scanSeg4Cols(seg))
                                return(FALSE);
                        }
                    }
                }
            }
        }

        char numBuffer[32];
        msgR("     Total COL: %s\n", prettyNumberString(colList.size(), numBuffer));
        #ifdef _DEVMODE
        msgR("COL scan time: %.3f\n", (getTimeStamp() - startTime));
        #endif
    }
    CATCH()
    return(FALSE);
}

// Locate vftables
static BOOL scanSeg4Vftables(segment_t *seg, eaRefMap &colMap)
{
	#ifdef _DEVMODE
	TIMESTAMP startTime = getTimeStamp();
	#endif

	char name[64];
    if (get_true_segm_name(seg, name, SIZESTR(name)) <= 0)
        strcpy(name, "???");
    msgR(" N: \"%s\", A: "EAFORMAT"-"EAFORMAT", S: %s. Pass 1\n", name, seg->startEA, seg->endEA, byteSizeString(seg->size()));


	RTTI::maxClassNameLength = 0;
	UINT found = 0;
    if (seg->size() >= sizeof(ea_t))
    {
        ea_t startEA = ((seg->startEA + sizeof(ea_t)) & ~((ea_t)(sizeof(ea_t) - 1)));
        ea_t endEA   = (seg->endEA - sizeof(ea_t));
        eaRefMap::iterator colEnd = colMap.end();

        for (ea_t ptr = startEA; ptr < endEA; ptr += sizeof(UINT))  //sizeof(ea_t)
        {
            // COL here?
            ea_t ea = getEa(ptr);
            eaRefMap::iterator it = colMap.find(ea);
            if (it != colEnd)
            {
                // yes, look for vftable one ea_t below
                ea_t vfptr  = (ptr + sizeof(ea_t));
                ea_t method = getEa(vfptr);
                // Points to code?
                if (segment_t *s = getseg(method))
                {
                    // yes,
                    if (s->type == SEG_CODE)
                    {
                        RTTI::processVftablePart1(vfptr, it->first);
                        it->second++, found++;
                    }
                }
            }

            if (WaitBox::isUpdateTime())
                if (WaitBox::updateAndCancelCheck())
                    return(TRUE);
        }
		if (found)
		{
			msgR(" N: \"%s\", A: "EAFORMAT"-"EAFORMAT", S: %s. Pass 2\n", name, seg->startEA, seg->endEA, byteSizeString(seg->size()));
			for (UINT i = 0; i < RTTI::classList.size(); i++)
				RTTI::classList[i].m_done = false;
			for (ea_t ptr = startEA; ptr < endEA; ptr += sizeof(UINT))  //sizeof(ea_t)
			{
				// COL here?
				ea_t ea = getEa(ptr);
				eaRefMap::iterator it = colMap.find(ea);
				if (it != colEnd)
				{
					// yes, look for vftable one ea_t below
					ea_t vfptr = (ptr + sizeof(ea_t));
					ea_t method = getEa(vfptr);
					// Points to code?
					if (segment_t *s = getseg(method))
					{
						// yes,
						if (s->type == SEG_CODE)
							RTTI::processVftablePart2(vfptr, it->first);
					}
				}

				if (WaitBox::isUpdateTime())
				if (WaitBox::updateAndCancelCheck())
					return(TRUE);
			}
		}
	}

	if (found)
	{
        char numBuffer[32];
		msgR("     Total VFT: %s	Longuest name: %d\n", prettyNumberString(found, numBuffer), RTTI::maxClassNameLength);
	}
	#ifdef _DEVMODE
	msgR("VFT scan time: %.3f\n", (getTimeStamp() - startTime));
	#endif
    return(FALSE);
}

bool lookupVftInClassList(LPCSTR demangledColName, ea_t* parentvft, UINT* parentCount) {
	for (UINT k = 0; k < RTTI::classList.size(); k++) {
		//msgR("\t\t\t\tThis name:%s\t%d\n", RTTI::classList[k].m_classname, RTTI::classList[k].m_done);
		if (0 == stricmp(RTTI::classList[k].m_className, demangledColName)) {
			if (!RTTI::classList[k].m_done) {
				vftable::processMembers(RTTI::classList[k].m_colName, RTTI::classList[k].m_start, &RTTI::classList[k].m_end, RTTI::classList[k].m_cTypeName, *parentvft, *parentCount);
				RTTI::classList[k].m_done = true;
			}
			*parentvft = RTTI::classList[k].m_vft;
			*parentCount = (RTTI::classList[k].m_end - RTTI::classList[k].m_start) / sizeof(ea_t);
			return true;
		}
	}
	return false;
}

static BOOL findVftables()
{
	try
	{
#ifdef _DEVMODE
		TIMESTAMP startTime = getTimeStamp();
#endif

		// COLs in a hash map for speed, plus match counts
		eaRefMap colMap;
		for (eaList::const_iterator it = colList.begin(), end = colList.end(); it != end; ++it)
			colMap[*it] = 0;

		// Usually in ".rdata", try first.
		stdext::hash_set<segment_t *> segSet;
		if (segment_t *seg = get_segm_by_name(".rdata"))
		{
			segSet.insert(seg);
			if (scanSeg4Vftables(seg, colMap))
				return(TRUE);
		}

		// And ones named ".data"
		int segCount = get_segm_qty();
		//if (colList.empty())
		{
			for (int i = 0; i < segCount; i++)
			{
				if (segment_t *seg = getnseg(i))
				{
					if (seg->type == SEG_DATA)
					{
						if (segSet.find(seg) == segSet.end())
						{
							char name[8];
							if (get_true_segm_name(seg, name, SIZESTR(name)) == SIZESTR(".data"))
							{
								if (strcmp(name, ".data") == 0)
								{
									segSet.insert(seg);
									if (scanSeg4Vftables(seg, colMap))
										return(TRUE);
								}
							}
						}
					}
				}
			}
		}

		// If still none found, try any remaining data type segments
		if (colList.empty())
		{
			for (int i = 0; i < segCount; i++)
			{
				if (segment_t *seg = getnseg(i))
				{
					if (seg->type == SEG_DATA)
					{
						if (segSet.find(seg) == segSet.end())
						{
							segSet.insert(seg);
							if (scanSeg4Vftables(seg, colMap))
								return(TRUE);
						}
					}
				}
			}
		}

		// Rebuild 'colList' with any that were not located
		if (!colList.empty())
		{
			colList.clear();
			for (eaRefMap::const_iterator it = colMap.begin(), end = colMap.end(); it != end; ++it)
			{
				if (it->second == 0)
					colList.push_front(it->first);
			}
		}

		for (UINT i = 0; i < RTTI::classList.size(); i++)
			RTTI::classList[i].m_done = false;
		for (UINT i = 0; i < RTTI::classList.size(); i++)
		{
			RTTI::classInfo* ci = &RTTI::classList[i];
			if (0 == i % 100)
				msgR("\t\tProcessing members in Classes:\t% 6d of % 6d\n", i + 1, RTTI::classList.size());
			//msgR("\t\tClass:\t%s\tvft:%08X\tcol:%08X\tCount:%d\tBaseClassIndex:%d\tnumBaseClasses:%d\n", ci->m_classname, ci->m_vft, ci->m_col, 
			//ci->m_list.size(), ci->m_baseClassIndex, ci->m_numBaseClasses);
			ea_t parentvft = BADADDR;
			UINT parentCount = 0;
			for (UINT j = ci->m_numBaseClasses - 1; j > 0; j--) {
				UINT k = j + ci->m_baseClassIndex;
				if (k < ci->m_bcdlist.size())
				{
					//msgR("\t\t\t%d %d %d\n", i, j, k);
					char demangledColName[MAXSTR];
					getPlainTypeName(ci->m_bcdlist[k].m_name, demangledColName);
					//msgR("\t\t\t%d %d %d\tparent:%s\tClass name:%s\n", i, j, k, ci->m_bcdlist[k].m_name, demangledColName);
					lookupVftInClassList(demangledColName, &parentvft, &parentCount);
				}
			}
			if (LPSTR compound = strstr(ci->m_className, "::")) {
				//msgR("\t\t\t\tCompound name:%s\n", compound);
				lookupVftInClassList(compound + 2, &parentvft, &parentCount);
			}
			vftable::processMembers(ci->m_colName, ci->m_start, &ci->m_end, ci->m_cTypeName, parentvft, parentCount);
			ci->m_done = true;
		}
#ifdef _DEVMODE
		msgR("vftable scan time: %.3f\n", (getTimeStamp() - startTime));
#endif
	}
	CATCHTRUE()

	return(FALSE);
}

// ================================================================================================

// Gather RTTI data
static BOOL getRttiData()
{
    // Free RTTI working data on return
    struct OnReturn  { ~OnReturn() { RTTI::freeWorkingData(); }; } onReturn;

    try
    {
        // ==== Locate __type_info_root_node
        BOOL aborted = FALSE;

        // ==== Find and process COLs
        msg("\nScanning for for RTTI Complete Object Locators.\n");
        refreshUI();
        if(findCols())
            return(TRUE);
        // typeDescList = TDs left that don't have a COL reference
        // colList = Located COLs

        // ==== Find and process vftables
        msg("\nScanning for vftables.\n");
        refreshUI();
        if(findVftables())
            return(TRUE);
		
		// colList = COLs left that don't have a vft reference

        // Could use the unlocated ref lists typeDescList & colList around for possible separate listing, etc.
        // They get cleaned up on return of this function anyhow.
    }
    CATCH()

    return(FALSE);
}
