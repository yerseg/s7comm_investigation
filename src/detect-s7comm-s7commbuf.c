/* Copyright (C) 2015-2018 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/*
 * TODO: Update the \author in this file and detect-s7comm-s7commbuf.h.
 * TODO: Update description in the \file section below.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author Sergey Kazmin <yourname@domain>
 *
 * Set up of the "s7comm_s7commbuf" keyword to allow content
 * inspections on the decoded s7comm application layer buffers.
 */

#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "app-layer-s7comm.h"
#include "detect-s7comm-s7commbuf.h"

#include "util-byte.h"

/**
 * \brief Regex for parsing the S7comm type string
 */
#define PARSE_REGEX_TYPE "^\\s*\"?\\s*type\\s*([0-9]+)\\s*\"?\\s*$"
static DetectParseRegex type_parse_regex;

/**
 * \brief Regex for parsing the S7comm function string
 */
#define PARSE_REGEX_FUNCTION "^\\s*\"?\\s*function\\s*([0-9]+)\\s*\"?\\s*$"
static DetectParseRegex function_parse_regex;

#define S7COMM_PROTOCOL_MIN_LEN 17
#define S7COMM_PROTOCOL_TYPE_HEADER_OFFSET 7
#define S7COMM_ROSCTR_HEADER_OFFSET (S7COMM_PROTOCOL_TYPE_HEADER_OFFSET + 1)
#define S7COMM_PDU_PTR_HEADER_OFFSET (S7COMM_PROTOCOL_TYPE_HEADER_OFFSET + 4)
#define S7COMM_PARAMS_LEN_HEADER_OFFSET (S7COMM_PROTOCOL_TYPE_HEADER_OFFSET + 6)
#define S7COMM_PDU_LEN_HEADER_OFFSET (S7COMM_PROTOCOL_TYPE_HEADER_OFFSET + 8)

#define S7COMM_PROTOCOL_TYPE_CODE 0x32

        
#ifdef UNITTESTS
static void DetectS7commS7commbufRegisterTests(void);
#endif

static int g_s7comm_id = 0;

void DetectS7commFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCEnter();
    DetectS7comm *s7comm = (DetectS7comm *) ptr;

    if (s7comm) {
        SCFree(s7comm);
    }
}

static DetectS7comm *DetectS7commTypeParse(DetectEngineCtx *de_ctx, const char *s7commstr)
{
    // Not ready!
    return NULL;
}

static DetectS7comm *DetectS7commFunctionParse(DetectEngineCtx *de_ctx, const char *s7commstr)
{
    SCEnter();
    DetectS7comm *s7comm = NULL;

    char arg[MAX_SUBSTRINGS];
    char *ptr = arg;
    int ov[MAX_SUBSTRINGS];
    int res;
    int ret;

    ret = DetectParsePcreExec(&function_parse_regex, s7commstr, 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 1)
        goto error;

    res = pcre_copy_substring(s7commstr, ov, MAX_SUBSTRINGS, 1, ptr, MAX_SUBSTRINGS);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    /* We have a correct S7comm function option */
    s7comm = (DetectS7comm *) SCCalloc(1, sizeof(DetectS7comm));
    if (unlikely(s7comm == NULL))
        goto error;

    if (StringParseUint8(&s7comm->function, 10, 0, (const char *)ptr) < 0) {
        SCLogError(SC_ERR_INVALID_VALUE, "Invalid value for s7comm function: %s", (const char *)ptr);
        goto error;
    }

    s7comm->has_function = true;

    SCLogNotice("will look for s7comm function %d", s7comm->function);

    SCReturnPtr(s7comm, "DetectS7comm");

error:
    if (s7comm != NULL)
        DetectS7commFree(de_ctx, s7comm);

    SCReturnPtr(NULL, "DetectS7comm");
}

int DetectS7commMatch(DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    uint8_t* payload = p->payload;
    uint8_t* payload_len = p->payload_len;
    DetectS7comm* s7comm = (DetectS7comm*)ctx;

    if (!(s7comm->has_function || s7comm->has_type)) {
        return 0;
    }

    if (payload_len < S7COMM_PROTOCOL_MIN_LEN) {
        SCLogNotice("payload length is too small");
        return 0;
    }

    if (PKT_IS_PSEUDOPKT(p)) {
        SCLogNotice("Pseudopkt detect");
        return 0; 
    }

    if (!PKT_IS_TCP(p)) {
        SCLogNotice("Transport protocol does not TCP");
        return 0; 
    }

    if (*(payload + S7COMM_PROTOCOL_TYPE_HEADER_OFFSET) != S7COMM_PROTOCOL_TYPE_CODE) {
        SCLogNotice("Protocol type not match with S7comm protocol: %d", *(payload + S7COMM_PROTOCOL_TYPE_HEADER_OFFSET));
        return 0;
    }

    int ret = 0;

    uint8_t rosctr = *(payload + S7COMM_ROSCTR_HEADER_OFFSET);
    if (s7comm->has_type && s7comm->type != rosctr) {
        SCLogNotice("Packet does not pass the filtering by message type (ROSCTR), actual rosctr = %d, rule = %d", rosctr, s7comm->type);
        return 0;
    }

    uint32_t s7comm_header_len = S7COMM_PROTOCOL_TYPE_HEADER_OFFSET + 10;
    if (rosctr == 0x03) { // Ack-data
        s7comm_header_len += 2;
    }

    uint8_t function = *(payload + s7comm_header_len);
    if (s7comm->has_function && s7comm->function != function) {
        SCLogNotice("Packet does not pass the filtering by function, actual function = %d, rule = %d", function, s7comm->function);
    
        return 0;
    } 

    SCLogNotice("PACKET PASSED the filtering, DETECT");
    return 1;
}

int DetectS7commSetup(DetectEngineCtx *de_ctx, Signature *s, const char *s7commstr)
{
    SCEnter();

    /* store list id. Content, pcre, etc will be added to the list at this
     * id. */
    s->init_data->list = g_s7comm_id;

    /* set the app proto for this signature. This means it will only be
     * evaluated against flows that are ALPROTO_S7COMM */

    DetectS7comm    *s7comm = NULL;
    SigMatch        *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_S7COMM) != 0)
        SCReturnInt(-1);

    if ((s7comm = DetectS7commTypeParse(de_ctx, s7commstr)) == NULL) {
        if ((s7comm = DetectS7commFunctionParse(de_ctx, s7commstr)) == NULL) {
            SCLogError(SC_ERR_PCRE_MATCH, "invalid s7comm option");
            if (s7comm != NULL)
                DetectS7commFree(de_ctx, s7comm);

            if (sm != NULL)
                SCFree(sm);

            SCReturnInt(-1);
        }
    }

    /* Okay so far so good, lets get this into a SigMatch and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
    {
        if (s7comm != NULL)
            DetectS7commFree(de_ctx, s7comm);

        if (sm != NULL)
            SCFree(sm);

        SCReturnInt(-1);
    }

    sm->type    = DETECT_AL_S7COMM_S7COMMBUF;
    sm->ctx     = (void *) s7comm;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH); //g_s7comm_id);

    SCReturnInt(0);
}

void DetectS7commS7commbufRegister(void)
{
    SCEnter();    

    sigmatch_table[DETECT_AL_S7COMM_S7COMMBUF].name = "s7comm";
    sigmatch_table[DETECT_AL_S7COMM_S7COMMBUF].desc = "S7comm content modififier to match on the s7comm buffers";
    sigmatch_table[DETECT_AL_S7COMM_S7COMMBUF].Match = DetectS7commMatch;
    sigmatch_table[DETECT_AL_S7COMM_S7COMMBUF].Setup = DetectS7commSetup;
    sigmatch_table[DETECT_AL_S7COMM_S7COMMBUF].Free = DetectS7commFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_S7COMM_S7COMMBUF].RegisterTests =
        DetectS7commS7commbufRegisterTests;
#endif

    sigmatch_table[DETECT_AL_S7COMM_S7COMMBUF].flags |= SIGMATCH_NOOPT;

    DetectSetupParseRegexes(PARSE_REGEX_TYPE, &type_parse_regex);
    DetectSetupParseRegexes(PARSE_REGEX_FUNCTION, &function_parse_regex);

    //g_s7comm_id = DetectBufferTypeGetByName("s7comm");

    SCLogNotice("S7comm application layer detect registered.");
}

#ifdef UNITTESTS
#include "tests/detect-s7comm-s7commbuf.c"
#endif
