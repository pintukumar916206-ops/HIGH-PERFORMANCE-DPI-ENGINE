#pragma once

#include "types.h"




class PacketSource {
public:
    virtual ~PacketSource() = default;


    virtual bool open(const std::string& resource) = 0;



    virtual bool nextPacket(RawPacket& pkt) = 0;


    virtual std::string name() const = 0;

    virtual void close() = 0;
};