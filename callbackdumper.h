#ifndef CALLBACKDUMPER_H
#define CALLBACKDUMPER_H

#include "dumperbase.h"

struct CallbackInfo
{
    int64_t m_callbackID;
    size_t m_callbackSize;
    std::vector<size_t> m_postedAt;
};

class CallbackDumper : public DumperBase
{
public:
    CallbackDumper(ClientModule* t_module);
    ~CallbackDumper();

    size_t FindCallbacks();
    std::map<int64_t, CallbackInfo>* GetCallbacks();


private:
    CallbackDumper();

    size_t GetCBRefs(size_t t_offset, std::vector<size_t>* t_out);
    bool GetCallbackInfoFromRef(size_t t_ref, size_t* t_cbID, size_t* t_cbSize);

    std::map<int64_t, CallbackInfo> m_callbacks;

    size_t m_postCallbackToAll;
    size_t m_postCallbackToPipe;
    size_t m_postCallbackToUI;
    size_t m_postCallbackToApp;
};

#endif // CALLBACKDUMPER_H
