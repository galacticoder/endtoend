#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <iostream>
#include <fstream>
#include <string>
#include <fmt/core.h>
#include <filesystem>
#include "../header-files/hostHttp.h"

namespace net = boost::asio;
namespace beast = boost::beast;
namespace http = boost::beast::http;

using tcp = boost::asio::ip::tcp;

void handle_request(beast::tcp_stream &stream, http::request<http::string_body> req, const std::string &path)
{
    http::response<http::string_body> res;
    res.version(req.version());
    res.keep_alive(req.keep_alive());
    res.set(http::field::server, "Beast");

    if (req.target().to_string() == "/" && std::filesystem::exists(path))
    {
        std::ifstream certFile(path, std::ios::binary);
        if (certFile)
        {
            std::string certContent((std::istreambuf_iterator<char>(certFile)), std::istreambuf_iterator<char>());
            res.result(http::status::ok);
            res.set(http::field::content_type, "application/x-x509-ca-cert");
            res.body() = certContent;
            res.prepare_payload();
        }
        else
        {
            res.result(http::status::internal_server_error);
            res.body() = "Certificate file could not be read";
            res.prepare_payload();
        }
    }
    else
    {
        res.result(http::status::not_found);
        res.body() = "Not Found";
        res.prepare_payload();
    }

    http::write(stream, res);
}

void startHost()
{
    try
    {
        const std::string path = "server-keys/server-cert.pem";
        std::filesystem::path current_path = std::filesystem::current_path();
        std::cout << "Current path: " << current_path << std::endl;

        net::io_context ioc;
        tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), 80));

        std::cout << "Cert hosting running on port 80" << std::endl;

        if (!std::filesystem::is_regular_file(path))
        {
            std::cerr << fmt::format("File ({}) does not exist", path) << std::endl;
        }

        while (true)
        {
            tcp::socket socket(ioc);
            acceptor.accept(socket);

            std::cout << "Client connected to HTTP host" << std::endl;

            beast::tcp_stream stream(std::move(socket));

            beast::flat_buffer buffer;
            http::request<http::string_body> req;
            http::read(stream, buffer, req);

            handle_request(stream, req, path);

            std::cout << "Client has received the cert file" << std::endl;

            stream.socket().shutdown(tcp::socket::shutdown_send);
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}
