#include <SDL.h>
#include <SDL_net.h>
#include <numeric>
#include <string>
#include "gdbstub.h"
#include "../dbg_debugger.h"
#include "../dbg_breakpoints.h"
#include "device/r4300/tlb.h"
#include "main/main.h"

#define BUFFER_SIZE 8192

char gdb_buffer[BUFFER_SIZE];

char gdb_send_buffer[BUFFER_SIZE];

TCPsocket gdb_socket;

int gdb_loop(void *x);
void gdb_send_signal_stop();
uint32_t DebugVirtualToPhysical(uint32_t address);


void gdbstub_init()
{
#if SDL_VERSION_ATLEAST(2,0,0)
    auto sdlthread = SDL_CreateThread(gdb_loop, "gdb_loop", NULL);
#else
//wait to make sure emulator is running?
//g_EmulatorRunning?
    auto sdlthread = SDL_CreateThread(gdb_loop, NULL);
#endif
}

int gdb_loop(void *x)
{
	/* initialize SDL */
	if(SDL_Init(0)==-1)
	{
		printf("SDL_Init: %s\n",SDL_GetError());
		exit(1);
	}

	/* initialize SDL_net */
	if(SDLNet_Init()==-1)
	{
		printf("SDLNet_Init: %s\n",SDLNet_GetError());
		exit(2);
	}

    IPaddress serverIP;

    SDLNet_ResolveHost(&serverIP, NULL, 5555);

    auto serverSocket = SDLNet_TCP_Open(&serverIP);

    if(serverSocket == nullptr)
    {
        auto error = SDLNet_GetError();
        printf("%s", error);
    }

    while(true)
    {
        //why isn't this blocking?
        gdb_socket = SDLNet_TCP_Accept(serverSocket);

        if(gdb_socket == nullptr)
        {
            auto error = SDLNet_GetError();
            //printf("%s", error);
        } else {
            
        }

        while(gdb_socket != nullptr)
        {

            //can this receive just '+'? can it receive multiple packets?
            auto recvLength = SDLNet_TCP_Recv(gdb_socket, gdb_buffer, BUFFER_SIZE - 1);
            if(recvLength <= 0) break;

            //don't have to clear send buffer or receive buffer
            //because of lengths and parsing

            gdb_buffer[recvLength] = '\0';

            //printf("%s", gdb_buffer);

            if(gdb_buffer[0] == '-' ) {
                //got resend request
            }

            auto index = 0;
            index += gdb_buffer[0] == '+' ? 1 : 0;
            // must check if no ack mode set really.

            if(gdb_buffer[0] == '\x03') {
                g_dbg_runstate = M64P_DBG_RUNSTATE_PAUSED;
            }

            //validate starts with $
            if(gdb_buffer[index] != '$') {
                // not sure
                continue;
            }

            //what if not found
            auto endOfmessage = strchr(gdb_buffer, '#');

            char twoDigitChecksum[3] = {*(endOfmessage + 1), *(endOfmessage + 2), '\0'};

            //what if fails
            auto checksum = strtol(twoDigitChecksum, nullptr, 16);

            //does this work right if start and end point at same address (empty message)
            //add offset for '+' and another for '$'
            //std::accumulate is no inclusive on the right
            //and so it will not read the '#' character endOfMessage points at
            auto check = std::accumulate(gdb_buffer + index + 1, endOfmessage, 0) % 256;

            if(checksum != check) {
                //error in communication
            }

            auto sendLength = 0;
            auto& qSupported = "qSupported";
            auto& vMustReplyEmpty = "vMustReplyEmpty";
            auto& questionMark = "?";
            auto& g = "g";
            auto& c = "c";
            auto& p = "p";
            auto& s = "s";
            auto& ctrlc = "\x03";
            //should be fine. Can read beyond packet, but not beyond buffer?
            if(memcmp(gdb_buffer + index + 1, qSupported, sizeof(qSupported) - 1) == 0) {
                auto& hwbreak = "hwbreak+;";
                //docs say stub should just respond with all features it supports to gdb
                //auto hwb = strstr(gdb_buffer + index + 1, hwbreak) == nullptr ? "" : hwbreak;
                //buffer size -2 to leave space for 2 checksum digits
                //auto charsWritten = snprintf(gdb_send_buffer, BUFFER_SIZE - 2, "+$%s#", hwbreak);
                //check if charsWritten > n given to snprintf

                //How to make this look at sizeof(buffer) or BUFFER_SIZE
                //preferably at compile time by force or optimization
                //checksum is knowable at compile time
                auto& supported = "$PacketSize=1400;hwbreak+;vContSupported+;#";
                auto charsWritten = strncpy(gdb_send_buffer, supported, sizeof(supported) - 1);
                auto checkSend = std::accumulate(supported + 1, supported + sizeof(supported) - 2, 0) % 256;

                //not needed, can just write to send buffer
                char checkSendBuff[3];
                auto eb = snprintf(checkSendBuff, sizeof(checkSendBuff), "%02x", checkSend);
                auto what = strncpy(gdb_send_buffer + sizeof(supported) - 1, checkSendBuff, sizeof(checkSendBuff));
                //minus nul term, add 2 for checksum digits
                sendLength = sizeof(supported) - 1 + 2;
            } else if(memcmp(gdb_buffer + index + 1, p, sizeof(p) - 1) == 0) {
                //NEEEDS TESTED
                //
                //
                //

                //what if the r4300 isn't ready?
                auto uh = r4300_regs(&g_dev.r4300);

                gdb_send_buffer[0] = '$';

                unsigned int regnum;
                sscanf(gdb_buffer + index + 2, "%x", &regnum);
                //only in general regs if number is 0-32
                auto what = snprintf(gdb_send_buffer + 1, 17, "%016llX", uh[regnum]);

                gdb_send_buffer[1 + 4 * 2] = '#';

                auto checkSend = std::accumulate(gdb_send_buffer + 1, gdb_send_buffer + 1 + 4 * 2, 0) % 256;
                //should write 3 or write 2? want to avoid /nul or not?
                auto eb = snprintf(gdb_send_buffer + 1 + 4 * 2 + 1, 3, "%02x", checkSend);
                //$ + 4 hex bytes as nibble pairs + # + 2 char checksum
                sendLength = 1 + 4 * 2 + 1 + 2;
            } else if(memcmp(gdb_buffer + index + 1, g, sizeof(g) - 1) == 0) {
                //by default on arch mips:4000
                //info reg shows the first 32-bits sent, even though registers are 64-bits of data?
                //Register data is placed in gdb from lsbyte to msbyte
                //"01234567" becomes "67452301"

                //what if the r4300 isn't ready?
                auto uh = r4300_regs(&g_dev.r4300);

                gdb_send_buffer[0] = '$';
                for(auto i = 0; i < 32; i++) {
                    auto what = snprintf(gdb_send_buffer + 1 + i * 16, 17, "%016llX", uh[i]);
                }

                auto cp0reg = r4300_cp0_regs(&g_dev.r4300.cp0);

                auto what = snprintf(gdb_send_buffer + 1 + 32 * 16, 17, "%016llX", cp0reg[CP0_STATUS_REG]);
                auto what1 = snprintf(gdb_send_buffer + 1 + 33 * 16, 17, "%016llX", g_dev.r4300.lo);
                auto what2 = snprintf(gdb_send_buffer + 1 + 34 * 16, 17, "%016llX", g_dev.r4300.hi);
                auto what3 = snprintf(gdb_send_buffer + 1 + 35 * 16, 17, "%016llX", cp0reg[CP0_BADVADDR_REG]);
                auto what4 = snprintf(gdb_send_buffer + 1 + 36 * 16, 17, "%016llX", cp0reg[CP0_CAUSE_REG]);
                auto what5 = snprintf(gdb_send_buffer + 1 + 37 * 16, 17, "%016llX", *r4300_pc(&g_dev.r4300));

                auto& pad = "01234567" "76543210" "01234567" "76543210" "01234567" "76543210"
                "01234567" "76543210" "01234567" "76543210" "01234567" "76543210";

                //auto what = strncpy(gdb_send_buffer + 1 + 32 * 16, pad, sizeof(pad));

                gdb_send_buffer[1 + 32 * 16 + sizeof(pad) - 1] = '#';

                auto checkSend = std::accumulate(gdb_send_buffer + 1, gdb_send_buffer + 1 + 32 * 16 + sizeof(pad) - 1, 0) % 256;
                //should write 3 or write 2? want to avoid /nul or not?
                auto eb = snprintf(gdb_send_buffer + 1 + 32 * 16 + sizeof(pad) - 1 + 1, 3, "%02x", checkSend);
                //minus nul term, add 2 for checksum digits, 2 for $ and #
                sendLength = 1 + 32 * 16 + sizeof(pad) - 1 + 1 + 2;
            } else if(gdb_buffer[index + 1] == 'G') {
                //what if the r4300 isn't ready?
                auto uh = r4300_regs(&g_dev.r4300);

                for(auto i = 0; i < 32; i++) {
                    uint64_t data;
                    char buf[17];
                    auto chars = strncpy(buf, gdb_buffer + 2 + i * 16, sizeof(buf) - 1);
                    buf[17] = '\0';
                    auto f = sscanf(buf, "%" SCNx64, &data);
                    uh[i] = data;
                }

                auto cp0reg = r4300_cp0_regs(&g_dev.r4300.cp0);

                uint64_t data;
                char buf[17];
                buf[17] = '\0';
                auto chars = strncpy(buf, gdb_buffer + 2 + 32 * 16, sizeof(buf) - 1);
                sscanf(buf, "%" SCNx64, &data);
                cp0reg[CP0_STATUS_REG] = data;
                chars = strncpy(buf, gdb_buffer + 2 + 33 * 16, sizeof(buf) - 1);
                sscanf(buf, "%" SCNx64, &data);
                g_dev.r4300.lo = data;
                chars = strncpy(buf, gdb_buffer + 2 + 34 * 16, sizeof(buf) - 1);
                sscanf(buf, "%" SCNx64, &data);
                g_dev.r4300.hi = data;
                chars = strncpy(buf, gdb_buffer + 2 + 35 * 16, sizeof(buf) - 1);
                sscanf(buf, "%" SCNx64, &data);
                cp0reg[CP0_BADVADDR_REG] = data;
                chars = strncpy(buf, gdb_buffer + 2 + 36 * 16, sizeof(buf) - 1);
                sscanf(buf, "%" SCNx64, &data);
                cp0reg[CP0_CAUSE_REG] = data;
                chars = strncpy(buf, gdb_buffer + 2 + 37 * 16, sizeof(buf) - 1);
                sscanf(buf, "%" SCNx64, &data);
                *r4300_pc(&g_dev.r4300) = data;
                
                gdb_send_buffer[0] = '$';
                auto what = strncpy(gdb_send_buffer + 1, "OK", 2);
                gdb_send_buffer[1 + sizeof("OK") - 1] = '#';

                auto checkSend = std::accumulate(gdb_send_buffer + 1, gdb_send_buffer + 1 + sizeof("OK") - 1, 0) % 256;
                //should write 3 or write 2? want to avoid /nul or not?
                auto eb = snprintf(gdb_send_buffer + 1 + sizeof("OK") - 1 + 1, 3, "%02x", checkSend);
                //1 for $, size of "OK" minus 1 for nul term char, 1 for #, 2 for checksum
                sendLength = 1 + sizeof("OK") - 1 + 1 + 2;
            } else if(memcmp(gdb_buffer + index + 1, questionMark, sizeof(questionMark) - 1) == 0) {
                //a ? is sent on connection by gdb

                if(g_dbg_runstate == M64P_DBG_RUNSTATE_PAUSED) {
                    auto& reply = "$S05#";
                    auto what = strncpy(gdb_send_buffer, reply, sizeof(reply));
                    auto checkSend = std::accumulate(reply + 1, reply + sizeof(reply) - 2, 0) % 256;
                    //should write 3 or write 2? want to avoid /nul or not?
                    auto eb = snprintf(gdb_send_buffer + sizeof(reply) - 1, 3, "%02x", checkSend);
                    //minus nul term, add 2 for checksum digits
                    sendLength = sizeof(reply) - 1 + 2;
                } //update_debugger will send the S05 in else case
                else g_dbg_runstate = M64P_DBG_RUNSTATE_PAUSED;
            } else if(memcmp(gdb_buffer + index + 1, s, sizeof(s) - 1) == 0) {
                debugger_step();//parse pause addr from request?
                //stop signal message sent in update_debugger

            } else if(memcmp(gdb_buffer + index + 1, c, sizeof(c) - 1) == 0) {
                g_dbg_runstate = M64P_DBG_RUNSTATE_RUNNING;
                debugger_step();

                //reply?
            } else if(gdb_buffer[index + 1] == 'Z' || gdb_buffer[index + 1] == 'z') {
                unsigned int address;
                unsigned int kind; //for read/write, this is size bytes to watch at addr
                auto w = sscanf(gdb_buffer + 4, "%x,%x", &address, &kind);

                auto execbk = gdb_buffer[index + 2] == '0' || gdb_buffer[index + 2] == '1';
                auto writebk = gdb_buffer[index + 2] == '2';
                auto readbk = gdb_buffer[index + 2] == '3';

                int flags = M64P_BKP_FLAG_ENABLED | (
                    execbk ? M64P_BKP_FLAG_EXEC :
                    writebk ? M64P_BKP_FLAG_WRITE :
                    readbk ? M64P_BKP_FLAG_READ :
                    M64P_BKP_FLAG_WRITE | M64P_BKP_FLAG_READ);

                if(!execbk) address = DebugVirtualToPhysical(address);

                m64p_breakpoint bkpt = {
                    .address = address,
                    .endaddr = execbk ? address : address + kind,
                    .flags = flags
                };

                if(gdb_buffer[index + 1] == 'Z') {
                    auto num = add_breakpoint_struct(&g_dev.mem, &bkpt);

                    if(num == -1) {
                        gdb_send_buffer[0] = '$';
                        auto what = strncpy(gdb_send_buffer + 1, "E01", sizeof("E01")-1);
                        gdb_send_buffer[1 + sizeof("E01") - 1] = '#';

                        auto checkSend = std::accumulate(gdb_send_buffer + 1, gdb_send_buffer + 1 + sizeof("E01") - 1, 0) % 256;
                        //should write 3 or write 2? want to avoid /nul or not?
                        auto eb = snprintf(gdb_send_buffer + 1 + sizeof("E01") - 1 + 1, 3, "%02x", checkSend);
                        //1 for $, size of "E01" minus 1 for nul term char, 1 for #, 2 for checksum
                        sendLength = 1 + sizeof("E01") - 1 + 1 + 2;
                    } else {
                        enable_breakpoint(&g_dev.mem, num);
                        gdb_send_buffer[0] = '$';
                        auto what = strncpy(gdb_send_buffer + 1, "OK", 2);
                        gdb_send_buffer[1 + sizeof("OK") - 1] = '#';

                        auto checkSend = std::accumulate(gdb_send_buffer + 1, gdb_send_buffer + 1 + sizeof("OK") - 1, 0) % 256;
                        //should write 3 or write 2? want to avoid /nul or not?
                        auto eb = snprintf(gdb_send_buffer + 1 + sizeof("OK") - 1 + 1, 3, "%02x", checkSend);
                        //1 for $, size of "OK" minus 1 for nul term char, 1 for #, 2 for checksum
                        sendLength = 1 + sizeof("OK") - 1 + 1 + 2;
                    }
                } else {
                    //safe to remove by address rather than number?
                    //gdb will always remove all on pause, and re-add all on step/continue, so yes?
                    remove_breakpoint_by_address(&g_dev.mem, address);

                    gdb_send_buffer[0] = '$';
                    auto what = strncpy(gdb_send_buffer + 1, "OK", 2);
                    gdb_send_buffer[1 + sizeof("OK") - 1] = '#';

                    auto checkSend = std::accumulate(gdb_send_buffer + 1, gdb_send_buffer + 1 + sizeof("OK") - 1, 0) % 256;
                    //should write 3 or write 2? want to avoid /nul or not?
                    auto eb = snprintf(gdb_send_buffer + 1 + sizeof("OK") - 1 + 1, 3, "%02x", checkSend);
                    //1 for $, size of "OK" minus 1 for nul term char, 1 for #, 2 for checksum
                    sendLength = 1 + sizeof("OK") - 1 + 1 + 2;
                }

            } else if(gdb_buffer[index + 1] == 'm') {
                unsigned int address; //potentially should be long, unsigned? format string issues. yes
                unsigned int length;
                sscanf(gdb_buffer + index + 2, "%x,%x", &address, &length);

                //this can crash probably if address is out of range
                //memory is stored in 32-bit words, little endian
                //address returned from fas_mem_access always be aligned to 32-bit boundary
                auto start = fast_mem_access_no_tlb_refill_exception(&g_dev.r4300, address);
                if(start == nullptr) {
                    //memory access failed, how does gdb expect failed address access to be handled?
                    auto& emptyReply = "$#00";
                    auto what = strncpy(gdb_send_buffer, emptyReply, sizeof(emptyReply));
                    //not caclulating the checksum for this one, baked it into string

                    //minus nul term, add 2 for checksum digits
                    sendLength = sizeof(emptyReply) - 1 + 2;
                } else {
                    gdb_send_buffer[0] = '$';

                    auto initialOffset = address & 0x3;
                    auto wordCount = ((initialOffset + length + 0x3) & ~0x3) >> 2;
                    for(auto wordi = 0; wordi < wordCount; wordi++) {
                        auto word = start[wordi];
                        //why did I have && bytei < length ? Seems wrong to me now
                        for(auto bytei = wordi == 0 ? initialOffset : 0, writei = (unsigned int)0; wordi * 4 - initialOffset + bytei < length && bytei < 4; bytei++, writei++) {
                            //byte order may be wrong
                            //since mips can be either way, and gdb can be manually set, not sure what is correct
                            //may want to load elf file, and see what that sets gdb to?
                            //then make send in correct order for that setting
                            auto byte = (word >> (3 - bytei) * 8) & 0xFF;
                            auto what = snprintf(gdb_send_buffer + 1 + wordi * 4 + writei * 2, 3, "%02x", byte);
                        }
                    }

                    gdb_send_buffer[1 + length * 2] = '#';

                    auto checkSend = std::accumulate(gdb_send_buffer + 1, gdb_send_buffer + 1 + length * 2, 0) % 256;
                    //should write 3 or write 2? want to avoid /nul or not?
                    auto eb = snprintf(gdb_send_buffer + 1 + length * 2 + 1, 3, "%02x", checkSend);
                    //minus nul term, add 2 for checksum digits, 2 for $ and #
                    sendLength = 1 + length * 2 + 1 + 2;
                }
            } else if(gdb_buffer[index + 1] == 'M') {
                unsigned int address; //potentially should be long, unsigned? format string issues. yes
                unsigned int length;
                sscanf(gdb_buffer + index + 2, "%x,%x", &address, &length);

                //this can crash probably if address is out of range
                //memory is stored in 32-bit words, little endian
                //address returned from fas_mem_access always be aligned to 32-bit boundary
                auto start = fast_mem_access_no_tlb_refill_exception(&g_dev.r4300, address);
                if(start == nullptr) {
                    //this is an error, should return E NN thing
                    gdb_send_buffer[0] = '$';
                    auto what = strncpy(gdb_send_buffer + 1, "OK", 2);
                    gdb_send_buffer[1 + sizeof("OK") - 1] = '#';

                    auto checkSend = std::accumulate(gdb_send_buffer + 1, gdb_send_buffer + 1 + sizeof("OK") - 1, 0) % 256;
                    //should write 3 or write 2? want to avoid /nul or not?
                    auto eb = snprintf(gdb_send_buffer + 1 + sizeof("OK") - 1 + 1, 3, "%02x", checkSend);
                    //1 for $, size of "OK" minus 1 for nul term char, 1 for #, 2 for checksum
                    sendLength = 1 + sizeof("OK") - 1 + 1 + 2;
                } else {
                    auto initialOffset = address & 0x3;
                    auto wordCount = ((initialOffset + length + 0x3) & ~0x3) >> 2;
                    auto bytes = strchr(gdb_buffer, ':');
                    for(auto wordi = 0; wordi < wordCount; wordi++) {
                        auto word = &start[wordi];
                        for(auto bytei = wordi == 0 ? initialOffset : 0, writei = (unsigned int)0; wordi * 4 - initialOffset + bytei < length && bytei < 4; bytei++, writei++) {
                            unsigned int data;
                            char buf[3];
                            buf[2] = '\0';
                            auto chars = strncpy(buf, bytes + 1 + wordi * 4 + writei * 2, sizeof(buf) - 1);
                            auto w = sscanf(buf, "%02x", &data);

                            //modify existing word with this byte of data
                            auto mask = 0xFF << (3 - bytei) * 8;
                            *word &= ~mask;
                            *word |= data << (3 - bytei) * 8;
                        }
                    }

                    gdb_send_buffer[0] = '$';
                    auto what = strncpy(gdb_send_buffer + 1, "OK", 2);
                    gdb_send_buffer[1 + sizeof("OK") - 1] = '#';

                    auto checkSend = std::accumulate(gdb_send_buffer + 1, gdb_send_buffer + 1 + sizeof("OK") - 1, 0) % 256;
                    //should write 3 or write 2? want to avoid /nul or not?
                    auto eb = snprintf(gdb_send_buffer + 1 + sizeof("OK") - 1 + 1, 3, "%02x", checkSend);
                    //1 for $, size of "OK" minus 1 for nul term char, 1 for #, 2 for checksum
                    sendLength = 1 + sizeof("OK") - 1 + 1 + 2;
                }
            } else { //if(memcmp(gdb_buffer + index + 1, vMustReplyEmpty, sizeof(vMustReplyEmpty) - 1) == 0)
                //does this change with ack setting?
                auto& emptyReply = "$#00";
                auto what = strncpy(gdb_send_buffer, emptyReply, sizeof(emptyReply));
                //not caclulating the checksum for this one, baked it into string

                //minus nul term, add 2 for checksum digits
                sendLength = sizeof(emptyReply) - 1 + 2;
            }

            auto acklen = SDLNet_TCP_Send(gdb_socket, "+", 1);
            auto actualsendLength = SDLNet_TCP_Send(gdb_socket, gdb_send_buffer, sendLength);

            //if(sentLength < recvLength) break;

            //CLEAR BUFFERS
        }
    }
    //close socket?

    return 0;
}

void gdb_try_send_signal_stop() {
    if(gdb_socket == nullptr) return;
    gdb_send_signal_stop();
}

void gdb_send_signal_stop()
{
    char stopb[7];
    auto& reply = "$S05#";
    auto what = strncpy(stopb, reply, sizeof(reply));
    auto checkSend = std::accumulate(reply + 1, reply + sizeof(reply) - 2, 0) % 256;
    //should write 3 or write 2? want to avoid /nul or not?
    auto eb = snprintf(stopb + sizeof(reply) - 1, 3, "%02x", checkSend);
    auto sendLength = sizeof(reply) - 1 + 2;
    auto actualsendLength = SDLNet_TCP_Send(gdb_socket, stopb, sendLength);
}

uint32_t DebugVirtualToPhysical(uint32_t address)
{
    struct device* dev = &g_dev;
    struct r4300_core* r4300 = &dev->r4300;

    if ((address & UINT32_C(0xc0000000)) != UINT32_C(0x80000000)) {
        address = virtual_to_physical_address_no_tlb_refill_exception(r4300, address, 0);
        if (address == 0) {
            return 0;
        }
    }

    address &= UINT32_C(0x1fffffff);
    return address;
}
