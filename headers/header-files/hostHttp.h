#ifndef HTTPHOST
#define HTTPHOST

#include <iostream>
#include <boost/asio.hpp>
#include <boost/beast.hpp>

namespace net = boost::asio;
namespace beast = boost::beast;
namespace http = boost::beast::http;

// void handle_request(beast::tcp_stream &stream, http::request<http::string_body> req);
void startHost();
void startServerPingHandles();

#endif
