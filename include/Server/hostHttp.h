#pragma once

#include <iostream>
#include <boost/asio.hpp>
#include <boost/beast.hpp>

namespace net = boost::asio;
namespace beast = boost::beast;
namespace http = boost::beast::http;

void startHost();