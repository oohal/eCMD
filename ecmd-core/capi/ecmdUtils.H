//IBM_PROLOG_BEGIN_TAG
/* 
 * Copyright 2003,2016 IBM International Business Machines Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//IBM_PROLOG_END_TAG

#ifndef ecmdUtils_H
#define ecmdUtils_H
/**
 * @file ecmdUtils.H
 * @brief Useful functions for use throughout the ecmd C API
 *
 */


//--------------------------------------------------------------------
// Includes
//--------------------------------------------------------------------
#include <inttypes.h>
#include <string>
#include <vector>

#include <ecmdDefines.H>
#include <ecmdClientCapi.H>
#include <ecmdTraceDefines.H>

//----------------------------------------------------------------------
//  Constants
//----------------------------------------------------------------------

//--------------------------------------------------------------------
// Macros
//--------------------------------------------------------------------

#ifdef _LP64
#define UINT64_HEX_FORMAT "%lX"
#define UINT64_HEX16_FORMAT "%016lX"
#define UINT64_HEX16_PRESC_FORMAT "%.16lX"
#define UINT64_DEC_FORMAT "%ld"
#else
#define UINT64_HEX_FORMAT "%llX"
#define UINT64_HEX16_FORMAT "%016llX"
#define UINT64_HEX16_PRESC_FORMAT "%.16llX"
#define UINT64_DEC_FORMAT "%lld"
#endif


//----------------------------------------------------------------------
//  User Types
//----------------------------------------------------------------------
#ifndef DOCUMENTATION
#if !defined(ECMD_STRIP_DEBUG) && !defined(ECMD_PERLAPI)
/**
 @brief Used by the eCMD Function parm trace printer
*/
typedef enum {
  ECMD_FPP_RETOUT,                      ///< Designates the failing return code out of the api function
  ECMD_FPP_FUNCTIONIN,                  ///< Designates the call in of the api function
  ECMD_FPP_FUNCTIONOUT,                 ///< Designatest the call out of the api function
  ECMD_FPP_JUSTIN,                      ///< Designatest the call in of the api function in debug 8 mode
  ECMD_FPP_JUSTOUT                      ///< Designatest the call out of the api function in debug 8 mode and rc==0
} efppInOut_t;

/**
 @brief Used by the eCMD Function Timer
*/
typedef enum {
  ECMD_TMR_FUNCTIONIN,                  ///< Designates the call in of the api function
  ECMD_TMR_FUNCTIONOUT,                 ///< Designates the call out of the api function
  ECMD_TMR_LOADDLL,                     ///< Load of the DLL
  ECMD_TMR_UNLOADDLL                    ///< Unload of the DLL
} etmrInOut_t;
#endif
#endif



/** @name eCMD Utility Functions */
//@{

/**
 @brief Reads data from data string into data buffer based on a format type
 @retval ECMD_SUCCESS if data is well-formatted, non-zero otherwise
 @param o_data ecmdDataBuffer where data from data string is placed.
 @param i_dataStr string of characters containing data
 @param i_format Flag that tells how to parse the data string, e.g., "b" = binary, "x" = hex left
 @param i_expectedLength If length of data is known before hand , should be passed is necessary for right aligned data that is not byte aligned lengths
 */
uint32_t ecmdReadDataFormatted (ecmdDataBuffer & o_data, const char * i_dataStr, std::string i_format, int i_expectedLength = 0);

/**
 @brief Converts decimal string to uint32_t
 @retval uint32_t value of converted input string
 @param i_decstr string of characters containing data
 */
uint32_t decToUInt32(const char *i_decstr);

/**
 @brief Formats data from data buffer into a string according to format flag and returns the string
 @return String of formatted data
 @param i_data ecmdDataBuffer where data to format is stored
 @param i_format Flag that tells how to parse the data into a string, e.g., "b" = binary, "x" = hex left
 @param i_address A base address value that can be used in formating certain data- i.e., data from memory
 @param i_endianMode The endianness with which to print the data
 */
std::string ecmdWriteDataFormatted(ecmdDataBuffer & i_data, std::string i_format, uint64_t i_address = 0, ecmdEndianMode_t i_endianMode = ECMD_BIG_ENDIAN);

/**
 @brief Print the bits header used in the output formats
 @param i_initCharOffset char offset on screen to start printing
 @param i_blockSize Binary block size (ie. column char size)
 @param i_numCols Number of columns to display
 @param i_endianMode The endianness with which to print the data
 @param i_maxBitWidth Maximum number of bits to display - this is actual data valid so we don't display more columns then we need
 @return String of formatted data
*/
std::string ecmdBitsHeader(int i_initCharOffset, int i_blockSize, int i_numCols, int i_maxBitWidth, ecmdEndianMode_t i_endianMode = ECMD_BIG_ENDIAN);

/**
 @brief Function calls ecmdQueryDllInfo and displays the output to stdout
 @retval ECMD_SUCCESS if successful
 @retval nonzero on failure
*/
uint32_t ecmdDisplayDllInfo();

#ifndef ECMD_REMOVE_SEDC_SUPPORT      
/**
 @brief Display the Scom data with the bit descriptions.
 @retval ECMD_SUCCESS if scom lookup and display was successful, non-zero otherwise
 @param i_target target for which scom data needs to be displayed.
 @param i_scomData Contains the address, as well as additional info, needed to lookup the scom
 @param i_data buffer that holds the scom data
 @param i_format posible values -v, -vs0, -vs1 for the information that needs to be displayed
 @param o_strData If passed in, then we load o_strData with what is printed to the screen
 */
uint32_t ecmdDisplayScomData(ecmdChipTarget & i_target, ecmdScomData & i_scomData, ecmdDataBuffer & i_data, const char* i_format, std::string *o_strData = NULL);
/**
 @brief Display the Scom data with the bit descriptions.
 @retval ECMD_SUCCESS if scom lookup and display was successful, non-zero otherwise
 @param i_target target for which scom data needs to be displayed.
 @param i_scomData Contains the address, as well as additional info, needed to lookup the scom
 @param i_data buffer that holds the scom data
 @param i_format posible values -v, -vs0, -vs1 for the information that needs to be displayed
 @param o_strData If passed in, then we load o_strData with what is printed to the screen
 */
uint32_t ecmdDisplayScomData(ecmdChipTarget & i_target, ecmdScomDataHidden & i_scomData, ecmdDataBuffer & i_data, const char* i_format, std::string *o_strData = NULL);
#endif

//@}

/***** INTERNAL eCMD UTILITY FUNCTIONS NOT FOR CLIENT USE ******/


#ifndef DOCUMENTATION
#if !defined(ECMD_STRIP_DEBUG) && !defined(ECMD_PERLAPI)
/**
 @brief Print the parameters pass to a given function.
 @param tCount is the trace count.
 @param inOut Tell Parm Printer if we are going into or out of the function
 @param fprototypeStr function prototype
 @param args function argument vector 
 */
void ecmdFunctionParmPrinter(int tCount, efppInOut_t inOut, const char * fprototypeStr, std::vector < void * > args);

/**
 @brief Time the spent inside of a dll call
 @param i_myTcount What step we are on
 @param i_timerState Going in or out
 @param i_funcName Name of the function
*/
void ecmdFunctionTimer(int32_t &i_myTcount, etmrInOut_t i_timerState, const char * i_funcName);
#endif

/**
 @brief Registers an extensions initstate pointer defect #18081
 @param i_initState Pointer to initState static so it can be reset later
 */
void ecmdRegisterExtensionInitState(bool* i_initState);

/**
 @brief Reset Extension initstate pointer to uninitialized
*/
void ecmdResetExtensionInitState();


#endif

/**
 @brief opens the groupscomdef parses the file
 @param i_filename file to open
 @param o_total_scomGroupRecord list of scomgroups that is returned
 @param use_filepos indicate a single scomgroup wanted, the scomgroup starts at this pos
 @param uniqueFilepos use this filepos if use_filepos is true

 */
uint32_t parse_groupscomdef_file(const std::string i_filename, std::list<scomGroupRecord_t> &o_total_scomGroupRecord, bool use_filepos = false, uint32_t uniqueFilepos = 0 );

/***** END INTERNAL eCMD UTILITY FUNCTIONS NOT FOR CLIENT USE ******/


#endif
