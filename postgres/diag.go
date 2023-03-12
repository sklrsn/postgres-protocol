package postgres

/**
Frontend(F)                                    Backend(B)
|             SSL Request ('S' or 'N')           |
|----------------------------------------------->|
|                                                |
|             SSL Response ('S')                 |
|<-----------------------------------------------|
|                                                |
|             Startup Message                    |
|----------------------------------------------->|
|                                                |
|             Password Request                   |
|<-----------------------------------------------|
|                                                |
|             Password Response                  |
|----------------------------------------------->|
|                                                |
|             AuthenticationOK                   |
|<-----------------------------------------------|
|                                                |
|             Parameter Status                   |
|<-----------------------------------------------|
|                                                |
|             Parameter Status                   |
|<-----------------------------------------------|
|                                                |
|             Parameter Status                   |
|<-----------------------------------------------|
|                                                |
|             BackendKeyData                     |
|<-----------------------------------------------|
|                                                |
|             ReadyForQuery                      |
|<-----------------------------------------------|
|                                                |
*/
