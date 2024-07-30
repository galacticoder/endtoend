#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <iostream>
#include <fstream>
#include <string>
#include "../header-files/fetchHttp.h"

namespace net = boost::asio;         // from <boost/asio.hpp>
namespace beast = boost::beast;      // from <boost/beast.hpp>
namespace http = boost::beast::http; // from <boost/beast/http.hpp>

using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>

void fetch_and_save_certificate(const std::string &host, const std::string &port, const std::string &certFilePath)
{
    try
    {
        net::io_context ioc;

        tcp::resolver resolver(ioc);
        tcp::resolver::results_type results = resolver.resolve(host, port);
        tcp::socket socket(ioc);
        net::connect(socket, results.begin(), results.end());

        http::request<http::string_body> req{http::verb::get, "server-keys/server-cert.pem", 11};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

        http::write(socket, req);

        beast::flat_buffer buffer;
        http::response<http::string_body> res;
        http::read(socket, buffer, res);

        std::ofstream certFile(certFilePath, std::ios::binary);
        if (certFile.is_open())
        {
            certFile << res.body();
            certFile.close();
            std::cout << "Server certificate saved to " << certFilePath << std::endl;
        }
        else
        {
            std::cerr << "Error opening file for writing: " << certFilePath << std::endl;
        }

        socket.shutdown(tcp::socket::shutdown_both);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

// int fetchMain()
// {
//     std::string host = "localhost";               // server ip
//     std::string port = "80";                      // port
//     std::string certFilePath = "server-cert.pem"; // save path

//     fetch_and_save_certificate(host, port, certFilePath);

//     return 0;
// }
