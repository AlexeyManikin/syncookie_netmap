//
// Created by alexey on 28.03.16.
//

#ifndef SYNFLOODPROTECT_LOGGER_H
#define SYNFLOODPROTECT_LOGGER_H

#include <stdio.h>
#include <stdlib.h>
#include <new>

// log4cpp logging facility
#include "log4cpp/RemoteSyslogAppender.hh"
#include "log4cpp/SyslogAppender.hh"
#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

void init_logging();

#endif //SYNFLOODPROTECT_LOGGER_H
