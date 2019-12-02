// =-=-=-=-=-=-=-
// irods includes
#include "authResponse.h"

// =-=-=-=-=-=-=-
#include "irods_error.hpp"
#include "irods_auth_plugin.hpp"
#include "irods_auth_constants.hpp"

// =-=-=-=-=-=-=-
// establish context - take the auth request results and massage them
// for the auth response call
inline irods::error pam_auth_establish_context(irods::plugin_context& _ctx )
{
  return SUCCESS();
} // pam_auth_establish_context

inline irods::error pam_auth_client_start(irods::plugin_context& _ctx,
                                          rcComm_t*              _comm,
                                          const char*            _context )
{
  return SUCCESS();
}

inline irods::error pam_auth_client_request(irods::plugin_context& _ctx,
                                            rcComm_t*              _comm )
{
  return SUCCESS();
}

irods::error pam_auth_client_response(irods::plugin_context& _ctx,
                                      rcComm_t*              _comm )
{
  return SUCCESS();
}

#ifdef RODS_SERVER
irods::error pam_auth_agent_start(irods::plugin_context&,
                                  const char*)
{
  return SUCCESS();
} // native_auth_success_stub
#endif


#ifdef RODS_SERVER
inline irods::error pam_auth_agent_request(irods::plugin_context& _ctx )
{
  return SUCCESS();
}
#endif

#ifdef RODS_SERVER
inline irods::error pam_auth_agent_response(irods::plugin_context& _ctx,
                                     authResponseInp_t*           _resp )
{
  return SUCCESS();
}
#endif

#ifdef RODS_SERVER
irods::error pam_auth_agent_verify(irods::plugin_context& ,
                                   const char* ,
                                   const char* ,
                                   const char* )
{
  return SUCCESS();
}
#endif

// =-=-=-=-=-=-=-
// derive a new pam_auth auth plugin from
// the auth plugin base class for handling
// native authentication
class pam2_auth_plugin : public irods::auth
{
public:
  pam2_auth_plugin(const std::string& _nm,
                   const std::string& _ctx ) :
    irods::auth(_nm, _ctx )
  {
  } // ctor

  ~pam2_auth_plugin()
  {
  }

}; // class pam_auth_plugin


// =-=-=-=-=-=-=-
// factory function to provide instance of the plugin
extern "C"
irods::auth* plugin_factory(
    const std::string& _inst_name,
    const std::string& _context ) {

    // =-=-=-=-=-=-=-
    // create an auth object
    pam2_auth_plugin* pam = new pam2_auth_plugin(
        _inst_name,
        _context );

    // =-=-=-=-=-=-=-
    // fill in the operation table mapping call
    // names to function names
    using namespace irods;
    using namespace std;
    pam->add_operation(
        AUTH_ESTABLISH_CONTEXT,
        function<error(plugin_context&)>(
            pam_auth_establish_context ) );
    pam->add_operation<rcComm_t*,const char*>(
        AUTH_CLIENT_START,
        function<error(plugin_context&,rcComm_t*,const char*)>(
            pam_auth_client_start ) );
    pam->add_operation<rcComm_t*>(
        AUTH_CLIENT_AUTH_REQUEST,
        function<error(plugin_context&,rcComm_t*)>(
            pam_auth_client_request ) );
    pam->add_operation<rcComm_t*>(
        AUTH_CLIENT_AUTH_RESPONSE,
        function<error(plugin_context&,rcComm_t*)>(
            pam_auth_client_response ) );
#ifdef RODS_SERVER
    pam->add_operation<const char*>(
        AUTH_AGENT_START,
        function<error(plugin_context&,const char*)>(
            pam_auth_agent_start ) );
    pam->add_operation(
        AUTH_AGENT_AUTH_REQUEST,
        function<error(plugin_context&)>(
            pam_auth_agent_request )  );
    pam->add_operation<authResponseInp_t*>(
        AUTH_AGENT_AUTH_RESPONSE,
        function<error(plugin_context&,authResponseInp_t*)>(
            pam_auth_agent_response ) );
    pam->add_operation<const char*,const char*,const char*>(
        AUTH_AGENT_AUTH_VERIFY,
        function<error(plugin_context&,const char*,const char*,const char*)>(
            pam_auth_agent_verify ) );
#endif
    irods::auth* auth = dynamic_cast< irods::auth* >( pam );

    return auth;

} // plugin_factory

