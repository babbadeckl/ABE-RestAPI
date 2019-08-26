#include "../include/handler.h"
#include <algorithm>
#include <string>
#include <openabe/openabe.h>

using namespace oabe;

//generated public and secret master keys ... they are here for testing purpose. Secret key (msk) MUST be stored safely!
std::string mpk = "AAAAFqpvykX8xmkctW++D1NIiWtuOAxtcGsAAAGooQFZsgEEtLIBABQK+uDcPn8ckXAKdeRaxukx+teEa8NfJdV+j1duMTHJHm1gq+IFZaRiKlYCdkMD5eZj7iIx8vbyqKkVi0z+c34DWMDz7/agz96pwnd5lbo68uWD4leqmX+IXf3jRUWliRQ/DaiQ7F0uVzfKCQvcp5IhpxLEW1Nfmncd0tyeHajNArgfqUMXF6ORdL1HcCzihKXd8YDoVu4Ty7C6LjfnVtYXhKoktOr12FucSmtY3HciF3abgbzj85wDl6t/LmUJuSB1MnmA/tsKW/1uN6fW10eetHajR0sYMNvYliiAS2aCFfu1k8cdhqY7b/6fvMm3pLFC3SaMXmym4rkZLqzShLuhAmcxoSSyoSECHtc4Rurt2X51sJ39tVVmyShhOsNN+Ax8fMyaoNJthluhAmcyoUSzoUECEacZxqi58THFzFw7Fyk6FK0pfC6jE2usDQ7w1pV+oQ8Ok4yRyCVf0vdFverVclKG+UF+NcFUtkrnYV75tRM9yKEBa6ElHQAAACAc0izE8hQB90QxIWJIFZ4KFBEgBS3M3bXhPVy6A23lWA==";
std::string msk = "AAAAFqpvysWm+0I6VYjDQ05ieKTdnUttc2sAAAAooQF5oSOxACAS5Ut8zTWvEbRNSHMdxXU0LKlP7ShASWURtXjy+LWC2A==";

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
        auto query_variables = message.relative_uri().split_query(http::uri::decode(message.relative_uri().query()));

        for(auto & query_variable : query_variables){
            ucout << "query: " << query_variable.first << "\n" << endl;
        }

        message.relative_uri().path();

        web::json::value root;
        auto relative_path = message.relative_uri().path();

        InitializeOpenABE();
        OpenABECryptoContext kpabe("KP-ABE");
        //kpabe.generateParams();
        kpabe.importPublicParams(mpk);
        kpabe.importSecretParams(msk);

        if(relative_path == "/gen_attribute_keys") {
                if(!query_variables["attribute"].empty()) {
                        string key_user;
                        kpabe.keygen(query_variables["attribute"], "key_attribute");
                        kpabe.exportUserKey("key_attribute", key_user);
                        root["key"] = web::json::value(U(key_user));
                }
        }
        else if(relative_path == "/gen_policy_keys") {
                if(!query_variables["policy"].empty()) {
                        // call the abe library to generate a key with a policy
                        string key_user;
                        kpabe.keygen(query_variables["policy"], "key_policy");
                        kpabe.exportUserKey("key_policy", key_user);
                        root["key"] = web::json::value(U(key_user));
                }
        }
        else if(relative_path == "/encrypt") {

                if(!query_variables["key"].empty() && !query_variables["plaintext"].empty()) {
                        // call the abe library to encrypt a plaintext with a user key
                        //import the master key and the user key into the context
                        kpabe.importPublicParams(mpk);
                        string cipher, pt1 = query_variables["plaintext"], pt2;
                        string encryption_attributes = query_variables["key"];
                        size_t index = 0;
                        //URL decoding of the pipe symbol "|" that is needed for the attribute list
                        while (true) {
                            index = encryption_attributes.find("%7C", index);
                            if (index == std::string::npos) break;
                            encryption_attributes.replace(index, 3, "|");
                            index += 3;
                        }
                        kpabe.encrypt(query_variables["key"],pt1,cipher);
                        root["ciphertext"] = web::json::value((cipher));
                }
        }
        else if(relative_path == "/decrypt") {
                if(!query_variables["key"].empty() && !query_variables["ciphertext"].empty()) {
                        // call the abe library to decrypt the ciphertext with the given key
                        string plaintext;
                        kpabe.importPublicParams(mpk);
                        kpabe.importUserKey("key_user", query_variables["key"]);
                        bool result = kpabe.decrypt("key_user",query_variables["ciphertext"],plaintext);
                        if(result) {
                                root["plaintext"] = web::json::value(U(plaintext));
                        } else {
                                root["ERROR"] = web::json::value("Encryption Failed: Your attributes do not match the required attributes!");
                        }
                }
        }
        else {
                root["ERROR"] = web::json::value("Your request is cannot be handled. Either you sent an unknown request or you are missing the correct parameters!");
        }
        ShutdownOpenABE();
        message.reply(status_codes::OK, root);
};
