#pragma once

#include "structure.h"

vmessserver_auth_runtime_t *vmessserverAuthCreate(tunnel_t *t);
void                        vmessserverAuthDestroy(vmessserver_auth_runtime_t *runtime);
bool                        vmessserverAuthLineInit(vmessserver_lstate_t *ls);
void                        vmessserverAuthSchedule(vmessserver_lstate_t *ls);
void                        vmessserverAuthLineDetach(vmessserver_lstate_t *ls);
bool                        vmessserverAuthAdmitInput(vmessserver_lstate_t *ls, size_t bytes);
bool                        vmessserverAuthResolve(vmessserver_lstate_t *ls);
bool vmessserverAuthSnapshot(vmessserver_auth_runtime_t *runtime, uint64_t *pending, uint64_t *bytes, uint64_t *cache);
void vmessserverAuthOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context);
void vmessserverAuthOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void vmessserverAuthOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
