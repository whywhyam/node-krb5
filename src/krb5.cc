#include <nan.h>
#include <string>
#include <cstring>
#include <node.h>
#include <v8.h>
extern "C" {
#include <krb5.h>
}


class krb5Worker : public Nan::AsyncWorker {
    public:
        krb5Worker(Nan::Callback *callback, const std::string& a_principal, const std::string& a_password):
            Nan::AsyncWorker(callback), m_principal(a_principal), m_password(a_password) {}
    
        ~krb5Worker() {}

        void Execute () {
            krb5_context context;
            krb5_principal principal;
            krb5_creds creds;

            int err;
            err = krb5_init_context(&context);
            if(err == 0)
            {
                err = krb5_parse_name(context, m_principal.c_str(), &principal);
                if(err == 0)
                {
                    err = krb5_get_init_creds_password(
                            context, 
                            &creds,
                            principal,
                            (char*) m_password.c_str(),
                            NULL,
                            NULL,
                            0,
                            NULL,
                            NULL
                            );

                    if(err == 0)
                    {
                        krb5_free_cred_contents(context, &creds);
                    }

                    krb5_free_principal(context, principal);
                }

                if(err != 0){  
                    const char* msg = krb5_get_error_message(context, err);
                    SetErrorMessage(msg);
                    krb5_free_error_message(context, msg);
                }

                krb5_free_context(context);
            }
            else {
                SetErrorMessage(std::strerror(err));
            }
        }

        void HandleOKCallback () {
            Nan::HandleScope();

            v8::Local<v8::Value> argv[] = { Nan::Null() };

            callback->Call(1, argv);
        }

    private:
        std::string m_principal;
        std::string m_password;
};

NAN_METHOD(Authenticate) {
    Nan::HandleScope();

	if(args.Length() < 3)
	{  	
		printf("too few arguments.\n");
        Nan::ReturnValue(Nan::New<v8::String>("too few arguments"));
	}

	if(!args[0]->IsString() || !args[1]->IsString() || !args[2]->IsFunction())
	{	
		printf("wrong arguments.\n");
        Nan::ReturnValue(Nan::New<v8::String>("wrong arguments"));
	}

    Nan::Callback *callback = new Nan::Callback(args[2].As<v8::Function>());
    std::string principal(*Nan::AsciiString(args[0]));
    std::string password(*Nan::AsciiString(args[1]));

    Nan::AsyncQueueWorker(new krb5Worker(callback, principal, password));
    Nan::ReturnUndefined();
}


void init(v8::Handle<v8::Object> exports) {
  exports->Set(Nan::New<v8::String>("authenticate"),
    Nan::New<v8::FunctionTemplate>(Authenticate)->GetFunction());
}

NODE_MODULE(krb5, init);

