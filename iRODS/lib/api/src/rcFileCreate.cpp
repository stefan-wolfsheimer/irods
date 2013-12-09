/*** Copyright (c), The Regents of the University of California            ***
 *** For more information please refer to files in the COPYRIGHT directory ***/
/* rcFileCreate.c - Client API call for fileCreate. Part of the
 * reoutine may be generated by a script
 */
#include "fileCreate.hpp"

int
rcFileCreate( rcComm_t *conn, fileCreateInp_t *fileCreateInp ) {
    int status;

    status = procApiRequest( conn, FILE_CREATE_AN, fileCreateInp, NULL,
                             ( void ** ) NULL, NULL );

    return ( status );
}

