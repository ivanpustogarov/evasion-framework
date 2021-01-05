/* License: GPL
 * Author: Ivan Pustogarov 
 * Original code by jbcayrou: https://github.com/jbcayrou/unicorn/commit/1f9f4849a7b5944c4539c0982f16cec0e61823a9#diff-41ff2aad60581299818d15491038e7bd
 * Date: 30 Dec 2019 */

#ifndef UC_CPREG_UTIL_H
#define UC_CPREG_UTIL_H

#include "arm_cpreg.h"
#include "arm_cpreg_info.h"

/* Defines enum constants for UC_ARM_CPREG_INFO_LIST list */
typedef enum  uc_arm_cpregid_enum {
    UC_ARM_CPREG_ID_LIST 
} uc_arm_cpregid_enum;

typedef struct  {
    char *name;
    uc_arm_cpregid_enum uc_reg_id;

    uint8_t cp;
    uint8_t opc1;
    uint8_t crn;
    uint8_t crm;
    //uint8_t opc0;
    uint8_t opc2;

} uc_arm_cp_reg;

const uc_arm_cp_reg ARM_CP_REGS_INFO[] =  {
    // { UC_ARM_REG_XXXXX,           cp, crn,crm,opc0,opc1,opc2 }

    // Manual entries

    // Automatical generated entries
    UC_ARM_CPREG_INFO_LIST       // C macro, see arm_cpgreg_info.h
};

#endif
