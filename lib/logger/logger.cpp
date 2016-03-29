//
// Created by alexey on 28.03.16.
//

#include <stdio.h>
#include <stdlib.h>
#include <new>
#include <fstream>

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

// log file
log4cpp::Category& logger = log4cpp::Category::getRoot();
std::string log_file_path = "/var/log/synflood.log";
int log_priority = log4cpp::Priority::DEBUG;

bool file_is_appendable(std::string path) {
    std::ofstream check_appendable_file;

    check_appendable_file.open(path.c_str(), std::ios::app);

    if (check_appendable_file.is_open()) {
        // all fine, just close file
        check_appendable_file.close();

        return true;
    } else {
        return false;
    }
}

void init_logging()
{
    if (!file_is_appendable(log_file_path)) {
        std::cerr << "Can't open log file " << log_file_path << " for writing! Please check file and folder permissions" << std::endl;
        exit(EXIT_FAILURE);
    }

    log4cpp::PatternLayout* layout = new log4cpp::PatternLayout();
    layout->setConversionPattern("%d [%p] %m%n");

    log4cpp::Appender* appender = new log4cpp::FileAppender("default", log_file_path);
    appender->setLayout(layout);

    logger.setPriority(log_priority);
    logger.addAppender(appender);

    logger << log4cpp::Priority::INFO << "Logger initialized!";
}