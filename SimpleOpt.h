// File:    SimpleOpt.h
// Library: SimpleOpt
// Author:  Brodie Thiesfield <brofield@jellycan.com>
// Source:  http://jellycan.com/SimpleOpt/
// Version: 1.4
//
// DISCLAIMER
// ==========
//  This code is released as public domain, you can do with it whatever you
//  like: use it, modify it, distribute it, sell it, delete it, or send
//  it to your mother-in-law.  I make no promises or guarantees that this
//  code will work correctly or at all. Use it completely at your own risk.
//
// CHARACTERSET ISSUES
// ===================
// This library is guaranteed to work correctly when:
//  * UNICODE mode (or)
//  * MBCS mode, and all entries in the option table use only ASCII characters
//
// The behaviour of this library is undefined in the following case:
//  * MBCS mode (and)
//  * option table entry uses non-ASCII string (e.g. the japanese text "--{na}{mae}")

#ifndef INCLUDED_SimpleOpt
#define INCLUDED_SimpleOpt


// error types
typedef enum _ESOError
{
    SO_SUCCESS          =  0,   // no error
    SO_OPT_INVALID      = -1,   // valid option format but not registered in the option table
    SO_OPT_MULTIPLE     = -2,   // multiple options matched the supplied option text
    SO_ARG_INVALID      = -3,   // argument was supplied but is not valid for this option
    SO_ARG_INVALID_TYPE = -4,   // argument was supplied in wrong format for this option
    SO_ARG_MISSING      = -5    // required argument was not supplied
} ESOError;

// SimpleOpt option flags
enum
{
    SO_O_MASK     = 0xFFFFU,    // mask for all valid SimpleOpt options
    SO_O_EXACT    = 0x0001U     // disallow partial matching of option names
};

// ArgType     Format                           Example
// -------     ------------------------------   ----------------------------------------
// SO_NONE     "foo -f --flag"                  "foo -f --flag"
// SO_REQ_SEP  "foo -s ARG --separate ARG"      "foo -s /tmp/foo.txt --separate /tmp/foo.txt"
// SO_REQ_CMB  "foo -cARG --combined=ARG"       "foo -c/tmp/foo.txt  --combined=/tmp/foo.txt"
// SO_OPT      "foo -o[ARG] --optional[=ARG]"   "foo -o/tmp/foo.txt --optional=/tmp/foo.txt"
//                                              (or) "foo -o --optional"
typedef enum _ESOArgType { SO_NONE, SO_REQ_SEP, SO_REQ_CMB, SO_OPT } ESOArgType;

// this option definition must be the last entry in the table
#define SO_END_OF_OPTIONS   { -1, 0, 0, SO_NONE }


template<class SOCHAR>
class CSimpleOptTempl
{
public:
    struct SOption {
        int         nId;            // ID to return for this flag. Optional but must be >= 0
        SOCHAR      cShortForm;     // short form of this arg, e.g. 'f' == "-f", '-' == "-", 0 == no short form
        SOCHAR *    pszLongForm;    // long form of this arg, e.g.  "file" == "--file", 0 == no long form
        ESOArgType  nArgType;       // type of argument accepted by this option
    };

    CSimpleOptTempl() { Init(0, 0, 0, 0); }
    CSimpleOptTempl(int argc, SOCHAR * argv[], const SOption * a_rgOptions, unsigned long a_ulFlags = 0) {
        Init(argc, argv, a_rgOptions, a_ulFlags);
	}

    /*
        Initialize the class in preparation for calling Next. The table of
        options pointed to by a_rgOptions does not need to be valid at the
        time that Init() is called. However on every call to Next() the
        table pointed to must be a valid options table with the last valid
        entry set to SO_END_OF_OPTIONS.

        NOTE: the array pointed to by a_argv will be modified by this
        class and must not be used or modified outside of member calls to
        this class.
    */
    void Init(int a_argc, SOCHAR * a_argv[], const SOption * a_rgOptions, unsigned long a_ulFlags = 0) {
        m_argc           = a_argc;
        m_argv           = a_argv;
        m_rgOptions      = a_rgOptions;
        m_nLastError     = SO_SUCCESS;
        m_nOptionIdx     = 0;
        m_nOptionId      = -1;
        m_pszOptionText  = 0;
        m_pszOptionArg   = 0;
        m_nNextOption    = 1;
        m_szShort[0]     = (SOCHAR)'-';		
        m_szShort[2]     = (SOCHAR)'\0';
        m_ulFlags        = a_ulFlags;
    }

    /*
        Call to advance to the next option. When all options have been processed
        it will return false. When true has been returned, you must check for an
        invalid or unrecognized option using the LastError() method. This will
        be return an error value other than SO_SUCCESS on an error. All standard
        data (e.g. OptionText(), OptionArg(), OptionId(), etc) will be available
        depending on the error.

        After all options have been processed, the remaining files from the
        command line can be processed in same order as they were passed to
        the program.

        Returns:
            true    option or error available for processing
            false   all options have been processed
    */
    bool Next() {
        // init for the next option
        m_nOptionIdx    = m_nNextOption;
        m_nOptionId     = -1;
        m_pszOptionText = 0;
        m_pszOptionArg  = 0;
        m_nLastError    = SO_SUCCESS;

        // next option, have we finished?
        int nOptIdx = m_nOptionIdx;
        while (nOptIdx < m_argc && m_argv[nOptIdx][0] != (SOCHAR)'-') {		
            ++nOptIdx;
        }
        if (nOptIdx >= m_argc) {
            return false;
        }
        m_pszOptionText = m_argv[nOptIdx];
        ++m_nNextOption;

        // find any combined argument string
        bool bIsLong = (m_pszOptionText[1] == (SOCHAR)'-');		
        SOCHAR * pCombinedArg = 0;
        if (bIsLong) {
            pCombinedArg = FindEquals(m_pszOptionText);
            if (pCombinedArg) {
                *pCombinedArg++ = (SOCHAR)'\0';
                m_pszOptionArg = pCombinedArg;
            }
        }
        else {
            if (m_pszOptionText[2]) {
                pCombinedArg = m_pszOptionText + 2;
                m_szShort[1] = m_pszOptionText[1];
                m_pszOptionText = m_szShort;
                m_pszOptionArg = pCombinedArg;
            }
        }

        // find this option in the options table
        int nShuffleCount = 1;
        int nTableIdx = bIsLong ?
            LookupOption(&m_pszOptionText[2]) : LookupOption(m_pszOptionText[1]);			
        if (nTableIdx < 0) {
            if (nOptIdx > m_nOptionIdx) {
                ShuffleArg(nOptIdx, nShuffleCount);
            }
            m_nLastError = (ESOError) nTableIdx; // error code
            return true;
        }
        m_nOptionId = m_rgOptions[nTableIdx].nId;

        // ensure that the arg type is valid
        ESOArgType nArgType = m_rgOptions[nTableIdx].nArgType;
        switch (nArgType) {
        case SO_NONE:
            if (pCombinedArg) {
                m_nLastError = SO_ARG_INVALID;
            }
            break;

        case SO_REQ_SEP:
            if (pCombinedArg) {
                m_nLastError = SO_ARG_INVALID_TYPE;
            }
            else if (nOptIdx+1 >= m_argc) {
                m_nLastError = SO_ARG_MISSING;
            }
            else {
                m_pszOptionArg = m_argv[nOptIdx+1];
                ++m_nNextOption;
                ++nShuffleCount;
            }
            break;

        case SO_REQ_CMB:
            if (!pCombinedArg) {
                m_nLastError = SO_ARG_MISSING;
            }
            break;

        case SO_OPT:
            // nothing to do
            break;
        }
        if (nOptIdx > m_nOptionIdx) {
            ShuffleArg(nOptIdx, nShuffleCount);
        }

        return true;
    }

    // access the details of the current option
    // NOTE: these functions are only valid after Next() returns true
    ESOError    LastError() const  { return m_nLastError; }
    int         OptionId() const   { return m_nOptionId; }
    SOCHAR *    OptionText() const { return m_pszOptionText; }
    SOCHAR *    OptionArg() const  { return m_pszOptionArg; }

    // access the files from the command line
    // NOTE: these functions are only valid after Next() returns false
    int         FileCount() const  { return m_argc - m_nOptionIdx; }
    SOCHAR *    File(int n) const  { return m_argv[m_nOptionIdx + n]; }
    SOCHAR **   Files() const      { return &m_argv[m_nOptionIdx]; }

private:
    // Shuffle arguments down towards the current front of the argv array
    // For example:
    //      m_nOptionIdx = 3;
    //      argv[] = { "0", "1", "2", "3", "4", "5", "6", "7", "8" };
    //
    //  ShuffleArg(5, 1) will move 1 entry from [5] to [3], e.g.
    //      argv[] = { "0", "1", "2", "5", "3", "4", "6", "7", "8" };
    //
    //  ShuffleArg(6, 2) will move 2 entries from [6] to [3], e.g.
    //      argv[] = { "0", "1", "2", "6", "7", "3", "4", "5", "8" };
    void ShuffleArg(int a_nSourceIdx, int a_nCount) {
        int n, nSrc = a_nSourceIdx + a_nCount - 1;
        SOCHAR * pszTemp;
        for (; a_nCount > 0; --a_nCount) {
            pszTemp = m_argv[nSrc];
            for (n = nSrc; n > m_nOptionIdx; --n) {
                m_argv[n] = m_argv[n-1];
            }
            m_argv[n] = pszTemp;
        }
    }

    // match on the long format strings. partial matches will be 
    // accepted only if that feature is enabled.
    int LookupOption(const SOCHAR * a_pszOption) const {
        int nBestMatch = -1;    // index of best match so far
        int nBestMatchLen = 0;  // matching characters of best match
        int nLastMatchLen = 0;  // matching characters of last best match
        
        for (int n = 0; m_rgOptions[n].nId >= 0; ++n) {
            int nMatchLen = CalcMatch(m_rgOptions[n].pszLongForm, a_pszOption);
            if (nMatchLen == -1) 
                return n;
            if (nMatchLen >= nBestMatchLen) {
                nLastMatchLen = nBestMatchLen;
                nBestMatchLen = nMatchLen;
                nBestMatch = n;
            }
        }

        // only partial matches or no match gets to here, ensure that we
        // don't return a partial match unless it is a clear winner
        if ((m_ulFlags & SO_O_EXACT) || nBestMatch == -1)
            return SO_OPT_INVALID;
        else 
            return (nBestMatchLen > nLastMatchLen) ? nBestMatch : SO_OPT_MULTIPLE;
    }

    // lookup an option in the options table using the short format
    int LookupOption(SOCHAR a_cOption) const {
        for (int n = 0; m_rgOptions[n].nId >= 0; ++n) {
            if (m_rgOptions[n].cShortForm) {
                if (!a_cOption && m_rgOptions[n].cShortForm == (SOCHAR)'-') {				
                    return n;
                }
                else if (m_rgOptions[n].cShortForm == a_cOption) {
                    return n;
                }
            }
        }
        return SO_OPT_INVALID;
    }

    // Find the '=' character within a string.
    SOCHAR * FindEquals(SOCHAR *s) const {
        for (; *s && *s != (SOCHAR)'='; ++s) /*loop*/;		
        return *s ? s : 0;
    }

    // calculate the number of characters that match (case-sensitive)
    // 0 = no match, > 0 == number of characters, -1 == perfect match
    int CalcMatch(const SOCHAR *s1, const SOCHAR *s2) const {
        if (!s1 || !s2) return 0;
        int nLen = 0;        
		for (; *s1 && *s1 == *s2; ++s1, ++s2, ++nLen) /*loop*/;
        return (!*s1 && !*s2) ? -1 : nLen;
    }

private:
    int             m_argc;          // argc to process
    SOCHAR **       m_argv;          // argv (rearranged during processing)
    const SOption * m_rgOptions;     // pointer to options table as passed in to soInit()
    ESOError        m_nLastError;    // error status from the last call
    int             m_nOptionIdx;    // index of the current option in argv
    int             m_nOptionId;     // id of the current option (or -1 if invalid option)
    SOCHAR *        m_pszOptionText; // text of the current option, e.g. "-f" or "--file"
    SOCHAR *        m_pszOptionArg;  // argument for the current option, e.g. "c:\blah.txt" (or 0 if no argument)
    int             m_nNextOption;   // index of the next option to be processed
    SOCHAR          m_szShort[3];    // used to return short option text when it has a combined option
    unsigned long   m_ulFlags;       // flags for parsing the command line 
};

// we supply both ASCII and WIDE char versions, plus a
// SOCHAR style that changes depending on the build setting
typedef CSimpleOptTempl<char>    CSimpleOptA;
typedef CSimpleOptTempl<wchar_t> CSimpleOptW;
#if defined(_UNICODE)
# define CSimpleOpt CSimpleOptW
#else
# define CSimpleOpt CSimpleOptA
#endif

#endif // INCLUDED_SimpleOpt
