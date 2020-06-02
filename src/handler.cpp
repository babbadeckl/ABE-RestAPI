#include "../include/handler.h"
#include <algorithm>
#include <string>
#include <openabe/openabe.h>

using namespace oabe;

//generated public and secret master keys ... they are here for testing purpose. Secret key (msk) MUST be stored safely!
std::string mpk = "AAAAFqpvykX8xmkctW++D1NIiWtuOAxtcGsAAAGooQFZsgEEtLIBABQK+uDcPn8ckXAKdeRaxukx+teEa8NfJdV+j1duMTHJHm1gq+IFZaRiKlYCdkMD5eZj7iIx8vbyqKkVi0z+c34DWMDz7/agz96pwnd5lbo68uWD4leqmX+IXf3jRUWliRQ/DaiQ7F0uVzfKCQvcp5IhpxLEW1Nfmncd0tyeHajNArgfqUMXF6ORdL1HcCzihKXd8YDoVu4Ty7C6LjfnVtYXhKoktOr12FucSmtY3HciF3abgbzj85wDl6t/LmUJuSB1MnmA/tsKW/1uN6fW10eetHajR0sYMNvYliiAS2aCFfu1k8cdhqY7b/6fvMm3pLFC3SaMXmym4rkZLqzShLuhAmcxoSSyoSECHtc4Rurt2X51sJ39tVVmyShhOsNN+Ax8fMyaoNJthluhAmcyoUSzoUECEacZxqi58THFzFw7Fyk6FK0pfC6jE2usDQ7w1pV+oQ8Ok4yRyCVf0vdFverVclKG+UF+NcFUtkrnYV75tRM9yKEBa6ElHQAAACAc0izE8hQB90QxIWJIFZ4KFBEgBS3M3bXhPVy6A23lWA==";
std::string msk = "AAAAFqpvysWm+0I6VYjDQ05ieKTdnUttc2sAAAAooQF5oSOxACAS5Ut8zTWvEbRNSHMdxXU0LKlP7ShASWURtXjy+LWC2A==";

std::string cp_mpk = "AAAAFqpvycmguLkB5YT8mXenb1DPbjptcGsAAAHToQFBsgEEtLIBACQfB8YgS/2OSSQhXnhq5Z2GzLSEIUyRrZlx7McLTRAlGh4UA7fRL+YfWJvTj8l5xnkOKjsONMWsRfbCwdzBwn0UzvrprKmo1BUMoLU0+C65fZhtx66Os8vsrMCqOH0SBiNXumqQrDRsTK0qxE9Z/7qqyxNDDu7HPJoAk0BHh0IRDyUWoL5AF9/Lehv74sJEI8LHBaOqzDW7bVQ+AetM+3AEar5VKQMRRAj1Reu/rH3hcHeCXW1KveejjPqcGO+xNREGX3xWDGd/Xxkk28di63QwgnV63qTKVeZRdu330cUwEtwqqGEYs661smakr+xYO83qrZttrFNblyCeJTC9E9KhAmcxoSSyoSEDFyRPaTAZUTc+D8xQiovNeG6k827tNCQWURoLFAJP8iuhA2cxYaEksqEhAgtD1+bvtiph2GyHIvPr826V9t2aETS7VElJlFiuTXhioQJnMqFEs6FBAh9I0y472UZHlL4YiYpput2HVWa+iOc/qujBSL5lZbEkHZAe7PbuBvZGPbb7e+Lbfcvdq3lPt8r1uTfL0D70vk2hAWuhJR0AAAAgw42EJ6VY9uBgC7m6CmfUCbGIE76karijsGPGwSqcF0M=";

std::string cp_msk = "AAAAFqpvye5OSVf3S0a/KGsmRn2hSnJtc2sAAAB3oQVhbHBoYaEjsQAgF5HUPk7+E141+x6CNRUdq5eK2B1PjT85YpdjybcB7MuhA2cyYaFEs6FBAwBD4ZPCMwDvcYRWxmZeXhKfKcL1yjNqZikzq5xB4KzgEcjnYqxkl7GXfl3An1V+6lq1bifGYN119nvWnNGLRoo=";

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
	OpenABECryptoContext cpabe("CP-ABE");
	//import public and secret params for both schemes
	kpabe.importPublicParams(mpk);
	kpabe.importSecretParams(msk);
	cpabe.importPublicParams(cp_mpk);
	cpabe.importSecretParams(cp_msk);

        if(relative_path == "/gen_attribute_keys") {
                if(!query_variables["attribute"].empty()) {
			if(!query_variables["scheme"].compare("kp")){
                        	string key_user;
                        	kpabe.keygen(query_variables["attribute"], "key_attribute");
                        	kpabe.exportUserKey("key_attribute", key_user);
                        	root["key"] = web::json::value(U(key_user));
			}
			else if(!query_variables["scheme"].compare("cp")){
				string key_user;
				cpabe.keygen(query_variables["attribute"], "key_attribute");
				cpabe.exportUserKey("key_attribute", key_user);
				root["key"] = web::json::value(U(key_user));
			}
			else {
				root["ERROR"] = web::json::value("No ABE Scheme specified or provided one is not supported. Please set the parameter 'scheme' to either 'cp' (ciphertext-policy ABE) or 'kp' (key-policy ABE)!");
			}
                }
		else {
			root["ERROR"] = web::json::value("No Attributes specified. Please set the parameter 'attribute'.");
		}
        }
        else if(relative_path == "/encrypt") {
                if(!query_variables["key"].empty() && !query_variables["plaintext"].empty()) {
                        // call the abe library to encrypt a plaintext with a user key
                        //import the master key and the user key into the context
                        string cipher, pt1 = query_variables["plaintext"], pt2;
			if(!query_variables["scheme"].compare("kp")){
                        	kpabe.encrypt(query_variables["key"],pt1,cipher);
                        	root["ciphertext"] = web::json::value((cipher));
			}
			else if(!query_variables["scheme"].compare("cp")){
				cpabe.encrypt(query_variables["key"],pt1,cipher);	
				root["ciphertext"] = web::json::value((cipher));
			}
                }
		else {
			root["ERROR"] = web::json::value("No Key or Plaintext specified! Please set the parameters 'key' and 'plaintext'.");
			root["ciphertext"] = web::json::value("");
		}
        }
        else if(relative_path == "/decrypt") {
                if(!query_variables["key"].empty() && !query_variables["ciphertext"].empty()) {
                        // call the abe library to decrypt the ciphertext with the given key
                        string plaintext;
			bool result = 0;
			if(!query_variables["scheme"].compare("kp")){
                        	kpabe.importUserKey("key_user", query_variables["key"]);
                        	result = kpabe.decrypt("key_user",query_variables["ciphertext"], plaintext);
			}

			else if(!query_variables["scheme"].compare("cp")){
				cpabe.importUserKey("key_user", query_variables["key"]);
				result = cpabe.decrypt("key_user",query_variables["ciphertext"], plaintext);

			}
			else {
				root["ERROR"] = web::json::value("No ABE Scheme specified or provided one is not supported. Please set the paramter 'scheme' to either 'cp' (ciphertext-policy ABE) or 'kp' (key-policy ABE)!");
			}
                        if(result) {
                                root["plaintext"] = web::json::value(U(plaintext));
                        } else {
                                root["ERROR"] = web::json::value("Encryption Failed: Your attributes do not match the required attributes!");
				root["plaintext"] = web::json::value("");
                        }
                }
		else {
			root["ERROR"] = web::json::value("No Key or Ciphertext specified. Please set the parameters 'key' and 'ciphertext'");
		}
        }
        else {
                root["ERROR"] = web::json::value("Your request is cannot be handled. Either you sent an unknown request or you are missing the correct parameters!");
        }
        ShutdownOpenABE();
        message.reply(status_codes::OK, root);
};
