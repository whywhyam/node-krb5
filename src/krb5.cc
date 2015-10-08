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

	if(info.Length() < 3)
	{  	
		printf("too few arguments.\n");
        info.GetReturnValue().Set(Nan::New("too few arguments").ToLocalChecked());
	}

	if(!info[0]->IsString() || !info[1]->IsString() || !info[2]->IsFunction())
	{	
		printf("wrong arguments.\n");
        info.GetReturnValue().Set(Nan::New("wrong arguments").ToLocalChecked());
	}

    Nan::Callback *callback = new Nan::Callback(info[2].As<v8::Function>());
    std::string principal(*v8::String::AsciiValue(info[0]));
    std::string password(*v8::String::AsciiValue(info[1]));

    Nan::AsyncQueueWorker(new krb5Worker(callback, principal, password));
    info.GetReturnValue().SetUndefined();
}


NAN_MODULE_INIT(init) {
    Nan::Set(target, Nan::New<v8::String>("authenticate").ToLocalChecked(),
    Nan::GetFunction(Nan::New<v8::FunctionTemplate>(Authenticate)).ToLocalChecked());
}

NODE_MODULE(krb5, init);

