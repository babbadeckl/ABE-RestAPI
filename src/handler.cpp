#include "../include/handler.h"
#include <string>
#include <openabe/openabe.h>

using namespace oabe;

std::string mpk;
std::string msk;
string test_key;

handler::handler()
{
        //ctor
}
handler::handler(utility::string_t url) : m_listener(url)
{
        m_listener.support(methods::GET, std::bind(&handler::handle_get, this, std::placeholders::_1));
}

handler::~handler()
{
        //dtor
}

void handler::handle_error(pplx::task<void>& t)
{
        try
        {
                t.get();
        }
        catch(...)
        {
                // log the error
        }
}

//
// Get Request
//
void handler::handle_get(http_request message)
{
        ucout <<  message.to_string() << endl;

        auto paths = http::uri::split_path(http::uri::decode(message.relative_uri().path()));
        auto query_variables = message.relative_uri().split_query(message.relative_uri().query());

        message.relative_uri().path();

        web::json::value root;

        auto relative_path = message.relative_uri().path();

        InitializeOpenABE();
        OpenABECryptoContext kpabe("KP-ABE");
        kpabe.generateParams();
        kpabe.exportPublicParams(mpk);
        kpabe.exportSecretParams(msk);

        if(relative_path.compare("/gen_attribute_keys") == 0) {
                if(!query_variables["attribute"].empty()) {
                        // call the abe library to generate a key with the attribute
                        string key_user;
                        kpabe.keygen(query_variables["attribute"], "key_attribute");
                        kpabe.exportUserKey("key_attribute", key_user);
                        test_key = key_user;
                        root["key"] = web::json::value(U(key_user));
                }
        }
        else if(relative_path.compare("/gen_policy_keys") == 0) {
                if(!query_variables["policy"].empty()) {
                        // call the abe library to generate a key with a policy
                        string key_user;
                        kpabe.keygen(query_variables["policy"], "key_policy");
                        kpabe.exportUserKey("key_policy", key_user);
                        root["key"] = web::json::value(U(key_user));
                }
        }
        else if(relative_path.compare("/encrypt") == 0) {

                if(!query_variables["key"].empty() && !query_variables["plaintext"].empty()) {
                        // call the abe library to encrypt the plaintext with the given key
                        kpabe.importPublicParams(mpk);
                        string cipher, pt1 = query_variables["plaintext"], pt2;
                        kpabe.encrypt(query_variables["key"],pt1,cipher);
                        root["ciphertext"] = web::json::value((cipher));
                }
        }
        else if(relative_path.compare("/decrypt") == 0) {
                if(!query_variables["key"].empty() && !query_variables["ciphertext"].empty()) {
                        // call the abe library to decrypt the ciphertext with the given key
                        string plaintext;
                        kpabe.importUserKey("key_user", query_variables["key"]);
                        bool result = kpabe.decrypt("key_user",query_variables["ciphertext"],plaintext);
                        ucout << "plaintext: " << plaintext << endl;
                        if(result) {
                                root["key"] = web::json::value(U(plaintext));
                        } else {
                                root["ERROR"] = web::json::value("You are not allowed to decrypt this ciphertext");
                        }
                }
        }
        else {
                // either no handler for request or one of the required parameters is missings
        }
        ShutdownOpenABE();
        message.reply(status_codes::OK, root);

        return;

};
