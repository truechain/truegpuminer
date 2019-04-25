#include <ethminer/buildinfo.h>
#include <libdevcore/Log.h>
#include <ethash/ethash.hpp>

#include "EthStratumClient.h"

#ifdef _WIN32
// Needed for certificates validation on TLS connections
#include <wincrypt.h>
#endif



#define DATALENGTH  2048	 //2048 520
#define PMTSIZE  4
#define TBLSIZE  16


using boost::asio::ip::tcp;
dataset_mgr _dsmgr;
int dataset_len = TBLSIZE*DATALENGTH*PMTSIZE*32;

EthStratumClient::EthStratumClient(int worktimeout, int responsetimeout)
  : PoolClient(),
    m_worktimeout(worktimeout),
    m_responsetimeout(responsetimeout),
    m_io_service(g_io_service),
    m_io_strand(g_io_service),
    m_socket(nullptr),
    m_workloop_timer(g_io_service),
    m_response_plea_times(64),
    m_txQueue(64),
    m_resolver(g_io_service),
    m_endpoints()
{
    m_jSwBuilder.settings_["indentation"] = "";

    // Initialize workloop_timer to infinite wait
    m_workloop_timer.expires_at(boost::posix_time::pos_infin);
    m_workloop_timer.async_wait(m_io_strand.wrap(boost::bind(
        &EthStratumClient::workloop_timer_elapsed, this, boost::asio::placeholders::error)));
    clear_response_pleas();
}


void EthStratumClient::init_socket()
{
    // Prepare Socket
    if (m_conn->SecLevel() != SecureLevel::NONE)
    {
        boost::asio::ssl::context::method method = boost::asio::ssl::context::tls_client;
        if (m_conn->SecLevel() == SecureLevel::TLS12)
            method = boost::asio::ssl::context::tlsv12;

        boost::asio::ssl::context ctx(method);
        m_securesocket = std::make_shared<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(
            m_io_service, ctx);
        m_socket = &m_securesocket->next_layer();

        if (getenv("SSL_NOVERIFY"))
        {
            m_securesocket->set_verify_mode(boost::asio::ssl::verify_none);
        }
        else
        {
            m_securesocket->set_verify_mode(boost::asio::ssl::verify_peer);
            m_securesocket->set_verify_callback(
                make_verbose_verification(boost::asio::ssl::rfc2818_verification(m_conn->Host())));
        }
#ifdef _WIN32
        HCERTSTORE hStore = CertOpenSystemStore(0, "ROOT");
        if (hStore == nullptr)
        {
            return;
        }

        X509_STORE* store = X509_STORE_new();
        PCCERT_CONTEXT pContext = nullptr;
        while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) != nullptr)
        {
            X509* x509 = d2i_X509(
                nullptr, (const unsigned char**)&pContext->pbCertEncoded, pContext->cbCertEncoded);
            if (x509 != nullptr)
            {
                X509_STORE_add_cert(store, x509);
                X509_free(x509);
            }
        }

        CertFreeCertificateContext(pContext);
        CertCloseStore(hStore, 0);

        SSL_CTX_set_cert_store(ctx.native_handle(), store);
#else
        char* certPath = getenv("SSL_CERT_FILE");
        try
        {
            ctx.load_verify_file(certPath ? certPath : "/etc/ssl/certs/ca-certificates.crt");
        }
        catch (...)
        {
            cwarn << "Failed to load ca certificates. Either the file "
                     "'/etc/ssl/certs/ca-certificates.crt' does not exist";
            cwarn << "or the environment variable SSL_CERT_FILE is set to an invalid or "
                     "inaccessible file.";
            cwarn << "It is possible that certificate verification can fail.";
        }
#endif
    }
    else
    {
        m_nonsecuresocket = std::make_shared<boost::asio::ip::tcp::socket>(m_io_service);
        m_socket = m_nonsecuresocket.get();
    }

    // Activate keep alive to detect disconnects
    unsigned int keepAlive = 10000;

#if defined(_WIN32)
    int32_t timeout = keepAlive;
    setsockopt(
        m_socket->native_handle(), SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(
        m_socket->native_handle(), SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    timeval tv{
        static_cast<suseconds_t>(keepAlive / 1000), static_cast<suseconds_t>(keepAlive % 1000)};
    setsockopt(m_socket->native_handle(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(m_socket->native_handle(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}
void EthStratumClient::init_dataset() {
    _dsmgr.init(dataset_len);
}

void EthStratumClient::connect()
{
    // Prevent unnecessary and potentially dangerous recursion
    if (m_connecting.load(std::memory_order::memory_order_relaxed))
        return;
    DEV_BUILD_LOG_PROGRAMFLOW(cnote, "EthStratumClient::connect() begin");

    // Start timing operations
    m_workloop_timer.expires_from_now(boost::posix_time::milliseconds(m_workloop_interval));
    m_workloop_timer.async_wait(m_io_strand.wrap(boost::bind(
        &EthStratumClient::workloop_timer_elapsed, this, boost::asio::placeholders::error)));

    // Reset status flags
    m_authpending.store(false, std::memory_order_relaxed);

    // Initializes socket and eventually secure stream
    if (!m_socket)
        init_socket();

    // Initialize a new queue of end points
    m_endpoints = std::queue<boost::asio::ip::basic_endpoint<boost::asio::ip::tcp>>();
    m_endpoint = boost::asio::ip::basic_endpoint<boost::asio::ip::tcp>();

    if (m_conn->HostNameType() == dev::UriHostNameType::Dns ||
        m_conn->HostNameType() == dev::UriHostNameType::Basic)
    {
        // Begin resolve all ips associated to hostname
        // calling the resolver each time is useful as most
        // load balancer will give Ips in different order
        m_resolver = tcp::resolver(m_io_service);
        tcp::resolver::query q(m_conn->Host(), toString(m_conn->Port()));

        // Start resolving async
        m_resolver.async_resolve(
            q, m_io_strand.wrap(boost::bind(&EthStratumClient::resolve_handler, this,
                   boost::asio::placeholders::error, boost::asio::placeholders::iterator)));
    }
    else
    {
        // No need to use the resolver if host is already an IP address
        m_endpoints.push(boost::asio::ip::tcp::endpoint(
            boost::asio::ip::address::from_string(m_conn->Host()), m_conn->Port()));
        m_io_service.post(m_io_strand.wrap(boost::bind(&EthStratumClient::start_connect, this)));
    }

    DEV_BUILD_LOG_PROGRAMFLOW(cnote, "EthStratumClient::connect() end");
}

void EthStratumClient::disconnect()
{
    // Prevent unnecessary recursion
    bool ex = false;
    if (!m_disconnecting.compare_exchange_strong(ex, true, memory_order_relaxed))
        return;

    m_connected.store(false, memory_order_relaxed);

    DEV_BUILD_LOG_PROGRAMFLOW(cnote, "EthStratumClient::disconnect() begin");

    // Cancel any outstanding async operation
    if (m_socket)
        m_socket->cancel();

    if (m_socket && m_socket->is_open())
    {
        try
        {
            boost::system::error_code sec;

            if (m_conn->SecLevel() != SecureLevel::NONE)
            {
                // This will initiate the exchange of "close_notify" message among parties.
                // If both client and server are connected then we expect the handler with success
                // As there may be a connection issue we also endorse a timeout
                m_securesocket->async_shutdown(
                    m_io_strand.wrap(boost::bind(&EthStratumClient::onSSLShutdownCompleted, this,
                        boost::asio::placeholders::error)));
                enqueue_response_plea();


                // Rest of disconnection is performed asynchronously
                DEV_BUILD_LOG_PROGRAMFLOW(cnote, "EthStratumClient::disconnect() end");
                return;
            }
            else
            {
                m_nonsecuresocket->shutdown(boost::asio::ip::tcp::socket::shutdown_both, sec);
                m_socket->close();
            }
        }
        catch (std::exception const& _e)
        {
            cwarn << "Error while disconnecting:" << _e.what();
        }
    }

    disconnect_finalize();
    DEV_BUILD_LOG_PROGRAMFLOW(cnote, "EthStratumClient::disconnect() end");
}

void EthStratumClient::disconnect_finalize()
{
    if (m_securesocket && m_securesocket->lowest_layer().is_open())
    {
        // Manage error code if layer is already shut down
        boost::system::error_code ec;
        m_securesocket->lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        m_securesocket->lowest_layer().close();
    }
    m_socket = nullptr;
    m_nonsecuresocket = nullptr;

    // Release locking flag and set connection status
#ifdef DEV_BUILD
    if (g_logOptions & LOG_CONNECT)
        cnote << "Socket disconnected from " << ActiveEndPoint();
#endif

    // Release session if exits
    if (m_session)
        m_conn->addDuration(m_session->duration());
    m_session = nullptr;

    m_authpending.store(false, std::memory_order_relaxed);
    m_disconnecting.store(false, std::memory_order_relaxed);
    m_txPending.store(false, std::memory_order_relaxed);

    if (!m_conn->IsUnrecoverable())
    {
        // If we got disconnected during autodetection phase
        // reissue a connect lowering stratum mode checks
        // m_canconnect flag is used to prevent never-ending loop when
        // remote endpoint rejects connections attempts persistently since the first
        if (!m_conn->StratumModeConfirmed() && m_conn->Responds())
        {
            // Repost a new connection attempt and advance to next stratum test
            if (m_conn->StratumMode() > 0)
            {
                m_conn->SetStratumMode(m_conn->StratumMode() - 1);
                m_io_service.post(
                    m_io_strand.wrap(boost::bind(&EthStratumClient::start_connect, this)));
                return;
            }
            else
            {
                // There are no more stratum modes to test
                // Mark connection as unrecoverable and trash it
                m_conn->MarkUnrecoverable();
            }
        }
    }

    // Clear plea queue and stop timing
    clear_response_pleas();
    m_solution_submitted_max_id = 0;

    // Put the actor back to sleep
    m_workloop_timer.expires_at(boost::posix_time::pos_infin);
    m_workloop_timer.async_wait(m_io_strand.wrap(boost::bind(
        &EthStratumClient::workloop_timer_elapsed, this, boost::asio::placeholders::error)));

    // Trigger handlers
    if (m_onDisconnected)
        m_onDisconnected();
}

void EthStratumClient::resolve_handler(
    const boost::system::error_code& ec, tcp::resolver::iterator i)
{
    if (!ec)
    {
        while (i != tcp::resolver::iterator())
        {
            m_endpoints.push(i->endpoint());
            i++;
        }
        m_resolver.cancel();

        // Resolver has finished so invoke connection asynchronously
        m_io_service.post(m_io_strand.wrap(boost::bind(&EthStratumClient::start_connect, this)));
    }
    else
    {
        cwarn << "Could not resolve host " << m_conn->Host() << ", " << ec.message();

        // Release locking flag and set connection status
        m_connecting.store(false, std::memory_order_relaxed);

        // We "simulate" a disconnect, to ensure a fully shutdown state
        disconnect_finalize();
    }
}

void EthStratumClient::start_connect()
{
    if (m_connecting.load(std::memory_order_relaxed))
        return;
    m_connecting.store(true, std::memory_order::memory_order_relaxed);

    if (!m_endpoints.empty())
    {
        // Pick the first endpoint in list.
        // Eventually endpoints get discarded on connection errors
        m_endpoint = m_endpoints.front();

        // Re-init socket if we need to
        if (m_socket == nullptr)
            init_socket();

#ifdef DEV_BUILD
        if (g_logOptions & LOG_CONNECT)
            cnote << ("Trying " + toString(m_endpoint) + " ...");
#endif

        clear_response_pleas();
        m_connecting.store(true, std::memory_order::memory_order_relaxed);
        enqueue_response_plea();
        m_solution_submitted_max_id = 0;

        // Start connecting async
        if (m_conn->SecLevel() != SecureLevel::NONE)
        {
            m_securesocket->lowest_layer().async_connect(m_endpoint,
                m_io_strand.wrap(boost::bind(&EthStratumClient::connect_handler, this, _1)));
        }
        else
        {
            m_socket->async_connect(m_endpoint,
                m_io_strand.wrap(boost::bind(&EthStratumClient::connect_handler, this, _1)));
        }
    }
    else
    {
        m_connecting.store(false, std::memory_order_relaxed);
        cwarn << "No more IP addresses to try for host: " << m_conn->Host();

        // We "simulate" a disconnect, to ensure a fully shutdown state
        disconnect_finalize();
    }
}

void EthStratumClient::workloop_timer_elapsed(const boost::system::error_code& ec)
{
    using namespace std::chrono;

    // On timer cancelled or nothing to check for then early exit
    if (ec == boost::asio::error::operation_aborted)
    {
        return;
    }

    // No msg from client (EthereumStratum/2.0.0)
    if (m_conn->StratumMode() == 3 && m_session)
    {
        auto s = duration_cast<seconds>(steady_clock::now() - m_session->lastTxStamp).count();
        if (s > ((int)m_session->timeout - 5))
        {
            // Send a message 5 seconds before expiration
            Json::Value jReq;
            jReq["id"] = unsigned(7);
            jReq["method"] = "mining.noop";
            send(jReq);
        }
    }


    if (m_response_pleas_count.load(std::memory_order_relaxed))
    {
        milliseconds response_delay_ms(0);
        steady_clock::time_point response_plea_time(
            m_response_plea_older.load(std::memory_order_relaxed));

        // Check responses while in connection/disconnection phase
        if (isPendingState())
        {
            response_delay_ms =
                duration_cast<milliseconds>(steady_clock::now() - response_plea_time);

            if ((m_responsetimeout * 1000) >= response_delay_ms.count())
            {
                if (m_connecting.load(std::memory_order_relaxed))
                {
                    // The socket is closed so that any outstanding
                    // asynchronous connection operations are cancelled.
                    m_socket->close();
                    return;
                }

                // This is set for SSL disconnection
                if (m_disconnecting.load(std::memory_order_relaxed) &&
                    (m_conn->SecLevel() != SecureLevel::NONE))
                {
                    if (m_securesocket->lowest_layer().is_open())
                    {
                        m_securesocket->lowest_layer().close();
                        return;
                    }
                }
            }
        }

        // Check responses while connected
        if (isConnected())
        {
            response_delay_ms =
                duration_cast<milliseconds>(steady_clock::now() - response_plea_time);

            // Delay timeout to a request
            if (response_delay_ms.count() >= (m_responsetimeout * 1000))
            {
                if (!m_conn->StratumModeConfirmed() && !m_conn->IsUnrecoverable())
                {
                    // Waiting for a response from pool to a login request
                    // Async self send a fake error response
                    Json::Value jRes;
                    jRes["id"] = unsigned(1);
                    jRes["result"] = Json::nullValue;
                    jRes["error"] = true;
                    clear_response_pleas();
                    m_io_service.post(m_io_strand.wrap(
                        boost::bind(&EthStratumClient::processResponse, this, jRes)));
                }
                else
                {
                    // Waiting for a response to solution submission
                    cwarn << "No response received in " << m_responsetimeout << " seconds.";
                    m_endpoints.pop();
                    clear_response_pleas();
                    m_io_service.post(
                        m_io_strand.wrap(boost::bind(&EthStratumClient::disconnect, this)));
                }
            }
            // No work timeout
            else if (m_session &&
                     (duration_cast<seconds>(steady_clock::now() - m_current_timestamp).count() >
                         m_worktimeout))
            {
                cwarn << "No new work received in " << m_worktimeout << " seconds.";
                m_endpoints.pop();
                clear_response_pleas();
                m_io_service.post(
                    m_io_strand.wrap(boost::bind(&EthStratumClient::disconnect, this)));
            }
        }
    }

    // Resubmit timing operations
    m_workloop_timer.expires_from_now(boost::posix_time::milliseconds(m_workloop_interval));
    m_workloop_timer.async_wait(m_io_strand.wrap(boost::bind(
        &EthStratumClient::workloop_timer_elapsed, this, boost::asio::placeholders::error)));
}

void EthStratumClient::connect_handler(const boost::system::error_code& ec)
{
    DEV_BUILD_LOG_PROGRAMFLOW(cnote, "EthStratumClient::connect_handler() begin");

    // Set status completion
    m_connecting.store(false, std::memory_order_relaxed);


    // Timeout has run before or we got error
    if (ec || !m_socket->is_open())
    {
        cwarn << ("Error  " + toString(m_endpoint) + " [ " + (ec ? ec.message() : "Timeout") +
                  " ]");

        // We need to close the socket used in the previous connection attempt
        // before starting a new one.
        // In case of error, in fact, boost does not close the socket
        // If socket is not opened it means we got timed out
        if (m_socket->is_open())
            m_socket->close();

        // Discard this endpoint and try the next available.
        // Eventually is start_connect which will check for an
        // empty list.
        m_endpoints.pop();
        m_io_service.post(m_io_strand.wrap(boost::bind(&EthStratumClient::start_connect, this)));

        DEV_BUILD_LOG_PROGRAMFLOW(cnote, "EthStratumClient::connect_handler() end1");
        return;
    }

    // We got a socket connection established
    m_conn->Responds(true);
    m_connected.store(true, memory_order_relaxed);

    m_message.clear();

    // Clear txqueue
    m_txQueue.consume_all([](std::string* l) { delete l; });

#ifdef DEV_BUILD
    if (g_logOptions & LOG_CONNECT)
        cnote << "Socket connected to " << ActiveEndPoint();
#endif

    if (m_conn->SecLevel() != SecureLevel::NONE)
    {
        boost::system::error_code hec;
        m_securesocket->lowest_layer().set_option(boost::asio::socket_base::keep_alive(true));
        m_securesocket->lowest_layer().set_option(tcp::no_delay(true));

        m_securesocket->handshake(boost::asio::ssl::stream_base::client, hec);

        if (hec)
        {
            cwarn << "SSL/TLS Handshake failed: " << hec.message();
            if (hec.value() == 337047686)
            {  // certificate verification failed
                cwarn << "This can have multiple reasons:";
                cwarn << "* Root certs are either not installed or not found";
                cwarn << "* Pool uses a self-signed certificate";
                cwarn << "* Pool hostname you're connecting to does not match the CN registered "
                         "for the certificate.";
                cwarn << "Possible fixes:";
#ifndef _WIN32
                cwarn << "* Make sure the file '/etc/ssl/certs/ca-certificates.crt' exists and "
                         "is accessible";
                cwarn << "* Export the correct path via 'export "
                         "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt' to the correct "
                         "file";
                cwarn << "  On most systems you can install the 'ca-certificates' package";
                cwarn << "  You can also get the latest file here: "
                         "https://curl.haxx.se/docs/caextract.html";
#endif
                cwarn << "* Double check hostname in the -P argument.";
                cwarn << "* Disable certificate verification all-together via environment "
                         "variable. See ethminer --help for info about environment variables";
                cwarn << "If you do the latter please be advised you might expose yourself to the "
                         "risk of seeing your shares stolen";
            }

            // This is a fatal error
            // No need to try other IPs as the certificate is based on host-name
            // not ip address. Trying other IPs would end up with the very same error.
            m_conn->MarkUnrecoverable();
            m_io_service.post(m_io_strand.wrap(boost::bind(&EthStratumClient::disconnect, this)));
            DEV_BUILD_LOG_PROGRAMFLOW(cnote, "EthStratumClient::connect_handler() end2");
            return;
        }
    }
    else
    {
        m_nonsecuresocket->set_option(boost::asio::socket_base::keep_alive(true));
        m_nonsecuresocket->set_option(tcp::no_delay(true));
    }

    // Clean buffer from any previous stale data
    m_sendBuffer.consume(4096);
    clear_response_pleas();

    /*

    If connection has been set-up with a specific scheme then
    set it's related stratum version as confirmed.

    Otherwise let's go through an autodetection.

    Autodetection process passes all known stratum modes.
    - 1st pass EthStratumClient::ETHEREUMSTRATUM2 (3)
    - 2nd pass EthStratumClient::ETHEREUMSTRATUM  (2)
    - 3rd pass EthStratumClient::ETHPROXY         (1)
    - 4th pass EthStratumClient::STRATUM          (0)
    */

    if (m_conn->Version() < 999)
    {
        m_conn->SetStratumMode(m_conn->Version(), true);
    }
    else
    {
        if (!m_conn->StratumModeConfirmed() && m_conn->StratumMode() == 999)
            m_conn->SetStratumMode(3, false);
    }


    Json::Value jReq;
    jReq["id"] = unsigned(1);
    jReq["jsonrpc"] = "2.0";
    jReq["method"] = "etrue_submitLogin";
    jReq["params"] = Json::Value(Json::arrayValue);
    jReq["params"].append("0xb85150eb365e7df0941f0cf08235f987ba91506a");
    jReq["params"].append("admin@example.net");
    jReq["worker"] = m_conn->Workername();

    // Begin receive data
    recvSocketData();

    /*
    Send first message
    NOTE !!
    It's been tested that f2pool.com does not respond with json error to wrong
    access message (which is needed to autodetect stratum mode).
    IT DOES NOT RESPOND AT ALL !!
    Due to this we need to set a timeout (arbitrary set to 1 second) and
    if no response within that time consider the tentative login failed
    and switch to next stratum mode test
    */
    enqueue_response_plea();
    send(jReq);

    DEV_BUILD_LOG_PROGRAMFLOW(cnote, "EthStratumClient::connect_handler() end");
}

void EthStratumClient::startSession()
{
    // Start a new session of data
    m_session = unique_ptr<Session>(new Session());
    m_current_timestamp = std::chrono::steady_clock::now();

    // Invoke higher level handlers
    if (m_onConnected)
        m_onConnected();
}

std::string EthStratumClient::processError(Json::Value& responseObject)
{
    std::string retVar;

    if (responseObject.isMember("error") &&
        !responseObject.get("error", Json::Value::null).isNull())
    {
        if (responseObject["error"].isConvertibleTo(Json::ValueType::stringValue))
        {
            retVar = responseObject.get("error", "Unknown error").asString();
        }
        else if (responseObject["error"].isConvertibleTo(Json::ValueType::arrayValue))
        {
            for (auto i : responseObject["error"])
            {
                retVar += i.asString() + " ";
            }
        }
        else if (responseObject["error"].isConvertibleTo(Json::ValueType::objectValue))
        {
            for (Json::Value::iterator i = responseObject["error"].begin();
                 i != responseObject["error"].end(); ++i)
            {
                Json::Value k = i.key();
                Json::Value v = (*i);
                retVar += (std::string)i.name() + ":" + v.asString() + " ";
            }
        }
    }
    else
    {
        retVar = "Unknown error";
    }

    return retVar;
}

void EthStratumClient::processExtranonce(std::string& enonce)
{
    m_session->extraNonceSizeBytes = enonce.length();
    cnote << "Extranonce set to " EthWhite << enonce << EthReset;
    enonce.resize(16, '0');
    m_session->extraNonce = std::stoul(enonce, nullptr, 16);
}
void EthStratumClient::processResponse(Json::Value& responseObject) {
    unsigned _id = responseObject.get("id", unsigned(0)).asUInt();
    bool _isSuccess = responseObject.get("error", Json::Value::null).empty();
    string _errReason = (_isSuccess ? "" : processError(responseObject));
    string _method = responseObject.get("method", "").asString();
    bool bnotify = _id == 0 && _method == "etrue_notify";

    if (!_isSuccess) {
        cwarn << "Pool sent an invalid jsonrpc message...,method:"<<_method<<"error:"<<_errReason;
        cwarn << "Disconnecting...";
        m_io_service.post(m_io_strand.wrap(boost::bind(&EthStratumClient::disconnect, this)));  // ????
        return;
    }

    if (_method == "etrue_getWork" || (_id == 0 && _method == "etrue_notify")) {
        handle_miner_work(bnotify,_id,responseObject);
    } else if (_method == "etrue_seedhash") {
        handle_dataset(_id,responseObject);
    }else if (_method == "etrue_get_version") {
        handle_get_version(_id,responseObject);
    } else if (_method == "etrue_get_hashrate") {
        handle_hashrate(_id,responseObject);
    } else if (_method == "etrue_get_hashrate") {
        handle_login(_id,responseObject);
    } else if (_id == 3) { 
        // result for submit
    } else {
        cwarn << "Got unknown method [" << _method << "] from pool. Discarding...";
        Json::Value jReq;
        jReq["jsonrpc"] = "2.0";
        jReq["id"] = _id;
        jReq["error"] = "Method not found";

        send(jReq);           
    }
}
bool EthStratumClient::handle_miner_work(bool bnotify,unsigned _id,Json::Value& responseObject)
{
    if (m_newjobprocessed) return true;
    // Json::Value jReq;
    Json::Value jPrm;
    if (!bnotify) {
        jPrm = responseObject.get("result", Json::Value::null);
    }else {
        jPrm = responseObject.get("params", Json::Value::null);
    }
    if (jPrm.isArray() && !jPrm.empty())
    {
        string headhash = jPrm.get(Json::Value::ArrayIndex(0), "").asString();
        string seedhash = jPrm.get(Json::Value::ArrayIndex(1), "").asString();
        string target = jPrm.get(Json::Value::ArrayIndex(2), "").asString();
        if (headhash.length() != 66 seedhash.length() != 66 || target.length() != 66) {
            cwarn << "Stratum miner work: invalid parameters";
            return false;
        }
        
        m_current.seed = h256(seedhash);
        m_current.header = h256(headhash);
        m_current.boundary = h256(target);
        m_current.startNonce = 0;
        m_current.exSizeBytes = 0;
        m_current_timestamp = std::chrono::steady_clock::now();
        m_current.ds = _dsmgr.get_dataset(seedhash);
        if (nullptr == m_current.ds) {
            // seedhash not match,will be update dataset
            // make sure stop all minering
            bool ex = false;
            if(m_ds_updating.compare_exchange_strong(ex, true, std::memory_order_relaxed)) {
                request_dataset(seedhash);
            }
            m_newjobprocessed = false;
        } else {
            m_newjobprocessed = true;
        }
        // This will signal to dispatch the job
        // at the end of the transmission. 
        return true;
    }
    return false;
}
bool EthStratumClient::handle_dataset(unsigned _id,Json::Value& responseObject)
{
    Json::Value jResult,jSeed;
    jResult = responseObject.get("result", Json::Value::null);
    if (jResult.isArray() && !jResult.empty()) {
        jSeed = jResult.get(Json::Value::ArrayIndex(0), Json::Value::null);
        if (!jSeed.empty()){
            int seed_count = jSeed.count();
            if(seed_count == (OFF_CYCLE_LEN + SKIP_CYCLE_LEN)) {
                string seed;
                uint8_t seeds[OFF_CYCLE_LEN + SKIP_CYCLE_LEN][16] = { 0 };
                string seed_hash;
                for(int i=0;i<seed_count;i++) {
                    seed = jSeed.get(Json::Value::ArrayIndex(i),"").asString();
                    if(seed.length() != 34) {
                        cwarn<<"Stratum update dataset: invalid seed,i:"<<i<<"seed:"<<seed;
                        return false;
                    }
                    memcpy(seed[i],h128(seed).data(),16);
                }
                seed_hash = jResult.get(Json::Value::ArrayIndex(1),"").asString();
                if (seed_hash.length() != 66) {
                    cwarn<<"Stratum update dataset: invalid seed_hash:"<<seed_hash;
                    return false;
                }               
                return make_and_update_ds(seed_hash,seeds);
            } else {
                cwarn<<"Stratum update dataset: invalid count,get:"<<seed_count<<"need:"<<(OFF_CYCLE_LEN + SKIP_CYCLE_LEN);
            }
        }
    }
    
    return false;
}
bool EthStratumClient::handle_hashrate(unsigned _id,Json::Value& responseObject)
{
    string rate;   // get hash rate
    Json::Value jReq;
    jReq["id"] = _id;
    jReq["jsonrpc"] = "2.0";
    jReq["method"] = "etrue_get_hashrate";
    jReq["result"] = rate;
    send(jReq);
    return false;
}
bool EthStratumClient::handle_get_version(unsigned _id,Json::Value& responseObject)
{
    Json::Value jReq;
    jReq["id"] = _id;
    jReq["jsonrpc"] = "2.0";
    jReq["method"] = "etrue_get_version";
    jReq["result"] = ethminer_get_buildinfo()->project_name_with_version;
    send(jReq);
           
    return true;
}
bool EthStratumClient::handle_login(unsigned _id,Json::Value& responseObject) {
    if (_id == 1) {
        Json::Value jResult = responseObject.get("result", Json::Value::null);
        if (jResult.empty() || (jResult.isBool() && !jResult.asBool())) {
            cwarn<<"login failed...will disconnect";
            m_authpending.store(false, std::memory_order_relaxed);
            m_io_service.post(m_io_strand.wrap(boost::bind(&EthStratumClient::disconnect, this)));
        } else {
            cwarn<<"login success...";
            m_authpending.store(true, std::memory_order_relaxed);
        }
    }
}
bool EthStratumClient::make_and_update_ds(string const& seed_hash,uint8_t seeds[OFF_CYCLE_LEN + SKIP_CYCLE_LEN][16])
{
    true_dataset ds(dataset_len);
    ds.make(seeds);
    _dsmgr.set_dataset(&ds);
    return false;
}
void EthStratumClient::request_dataset(string const &seedhash) {
    Json::Value jReq;
    jReq["jsonrpc"] = "2.0";
    jReq["id"] = 4;
    jReq["method"] = "etrue_seedhash";
    jReq["params"] = Json::Value(Json::arrayValue);
    jReq["params"].append(seedhash);
    send(jReq);  
}

void EthStratumClient::submitHashrate(uint64_t const& rate, string const& id)
{
    if (!isConnected())
        return;

    Json::Value jReq;
    jReq["id"] = unsigned(6);
    jReq["method"] = "etrue_get_hashrate";
    jReq["params"] = Json::Value(Json::arrayValue);
    jReq["params"].append(toCompactHex(rate, HexPrefix::DontAdd));
    jReq["error"] = Json::Value::null;
    
    send(jReq);
}

void EthStratumClient::submitSolution(const Solution& solution)
{
    if (!isAuthorized())
    {
        cwarn << "Solution not submitted. Not authorized.";
        return;
    }

    Json::Value jReq;

    unsigned id = 3;
    jReq["id"] = id;
    jReq["jsonrpc"] = "2.0";
    m_solution_submitted_max_id = max(m_solution_submitted_max_id, id);
    jReq["method"] = "etrue_submitWork";
    jReq["params"] = Json::Value(Json::arrayValue);
    jReq["params"].append(toHex(solution.nonce, HexPrefix::Add));
    jReq["params"].append(solution.work.header.hex(HexPrefix::Add));
    jReq["params"].append(solution.mixHash.hex(HexPrefix::Add));
    if (!m_conn->Workername().empty())
        jReq["worker"] = m_conn->Workername();

    enqueue_response_plea();
    send(jReq);
}

void EthStratumClient::recvSocketData()
{
    if (m_conn->SecLevel() != SecureLevel::NONE)
    {
        async_read(*m_securesocket, m_recvBuffer, boost::asio::transfer_at_least(1),
            m_io_strand.wrap(boost::bind(&EthStratumClient::onRecvSocketDataCompleted, this,
                boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)));
    }
    else
    {
        async_read(*m_nonsecuresocket, m_recvBuffer, boost::asio::transfer_at_least(1),
            m_io_strand.wrap(boost::bind(&EthStratumClient::onRecvSocketDataCompleted, this,
                boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)));
    }
}

void EthStratumClient::onRecvSocketDataCompleted(
    const boost::system::error_code& ec, std::size_t bytes_transferred)
{
    // Due to the nature of io_service's queue and
    // the implementation of the loop this event may trigger
    // late after clean disconnection. Check status of connection
    // before triggering all stack of calls

    if (!ec)
    {
        // DO NOT DO THIS !!!!!
        // std::istream is(&m_recvBuffer);
        // std::string message;
        // getline(is, message)
        /*
        There are three reasons :
        1 - Previous async_read_until calls this handler (aside from error codes)
            with the number of bytes in the buffer's get area up to and including
            the delimiter. So we know where to split the line
        2 - Boost's documentation clearly states that after a succesfull
            async_read_until operation the stream buffer MAY contain additional
            data which HAVE to be left in the buffer for subsequent read operations.
            If another delimiter exists in the buffer then it will get caught
            by the next async_read_until()
        3 - std::istream is(&m_recvBuffer) will CONSUME ALL data in the buffer
            thus invalidating the previous point 2
        */

        // Extract received message and free the buffer
        std::string rx_message(
            boost::asio::buffer_cast<const char*>(m_recvBuffer.data()), bytes_transferred);
        m_recvBuffer.consume(bytes_transferred);
        m_message.append(rx_message);

        // Process each line in the transmission
        // NOTE : as multiple jobs may come in with
        // a single transmission only the last will be dispatched
        m_newjobprocessed = false;
        std::string line;
        size_t offset = m_message.find("\n");
        while (offset != string::npos)
        {
            if (offset > 0)
            {
                line = m_message.substr(0, offset);
                boost::trim(line);

                if (!line.empty())
                {
                    // Out received message only for debug purpouses
                    if (g_logOptions & LOG_JSON)
                        cnote << " << " << line;

                    // Test validity of chunk and process
                    Json::Value jMsg;
                    Json::Reader jRdr;
                    if (jRdr.parse(line, jMsg))
                    {
                        try
                        {
                            // Run in sync so no 2 different async reads may overlap
                            processResponse(jMsg);
                        }
                        catch (const std::exception& _ex)
                        {
                            cwarn << "Stratum got invalid Json message : " << _ex.what();
                        }
                    }
                    else
                    {
                        string what = jRdr.getFormattedErrorMessages();
                        boost::replace_all(what, "\n", " ");
                        cwarn << "Stratum got invalid Json message : " << what;
                    }
                }
            }

            m_message.erase(0, offset + 1);
            offset = m_message.find("\n");
        }

        // There is a new job - dispatch it
        if (m_newjobprocessed)
            if (m_onWorkReceived)
                m_onWorkReceived(m_current);

        // Eventually keep reading from socket
        if (isConnected())
            recvSocketData();
    }
    else
    {
        if (isConnected())
        {
            if (m_authpending.load(std::memory_order_relaxed))
            {
                cwarn << "Error while waiting for authorization from pool";
                cwarn << "Double check your pool credentials.";
                m_conn->MarkUnrecoverable();
            }

            if ((ec.category() == boost::asio::error::get_ssl_category()) &&
                (ERR_GET_REASON(ec.value()) == SSL_RECEIVED_SHUTDOWN))
            {
                cnote << "SSL Stream remotely closed by " << m_conn->Host();
            }
            else if (ec == boost::asio::error::eof)
            {
                cnote << "Connection remotely closed by " << m_conn->Host();
            }
            else
            {
                cwarn << "Socket read failed: " << ec.message();
            }
            m_io_service.post(m_io_strand.wrap(boost::bind(&EthStratumClient::disconnect, this)));
        }
    }
}

void EthStratumClient::send(Json::Value const& jReq)
{
    std::string* line = new std::string(Json::writeString(m_jSwBuilder, jReq));
    m_txQueue.push(line);

    bool ex = false;
    if (m_txPending.compare_exchange_strong(ex, true, std::memory_order_relaxed))
        sendSocketData();
}

void EthStratumClient::sendSocketData()
{
    if (!isConnected() || m_txQueue.empty())
    {
        m_sendBuffer.consume(m_sendBuffer.capacity());
        m_txQueue.consume_all([](std::string* l) { delete l; });
        m_txPending.store(false, std::memory_order_relaxed);
        return;
    }

    std::string* line;
    std::ostream os(&m_sendBuffer);
    while (m_txQueue.pop(line))
    {
        os << *line << std::endl;
        // Out received message only for debug purpouses
        if (g_logOptions & LOG_JSON)
            cnote << " >> " << *line;

        delete line;
    }

    if (m_conn->SecLevel() != SecureLevel::NONE)
    {
        async_write(*m_securesocket, m_sendBuffer,
            m_io_strand.wrap(boost::bind(&EthStratumClient::onSendSocketDataCompleted, this,
                boost::asio::placeholders::error)));
    }
    else
    {
        async_write(*m_nonsecuresocket, m_sendBuffer,
            m_io_strand.wrap(boost::bind(&EthStratumClient::onSendSocketDataCompleted, this,
                boost::asio::placeholders::error)));
    }
}

void EthStratumClient::onSendSocketDataCompleted(const boost::system::error_code& ec)
{
    if (ec)
    {
        m_sendBuffer.consume(m_sendBuffer.capacity());
        m_txQueue.consume_all([](std::string* l) { delete l; });
        m_txPending.store(false, std::memory_order_relaxed);

        if ((ec.category() == boost::asio::error::get_ssl_category()) &&
            (SSL_R_PROTOCOL_IS_SHUTDOWN == ERR_GET_REASON(ec.value())))
        {
            cnote << "SSL Stream error : " << ec.message();
            m_io_service.post(m_io_strand.wrap(boost::bind(&EthStratumClient::disconnect, this)));
        }

        if (isConnected())
        {
            cwarn << "Socket write failed : " << ec.message();
            m_io_service.post(m_io_strand.wrap(boost::bind(&EthStratumClient::disconnect, this)));
        }
    }
    else
    {
        // Register last transmission tstamp to prevent timeout
        // in EthereumStratum/2.0.0
        if (m_session && m_conn->StratumMode() == 3)
            m_session->lastTxStamp = chrono::steady_clock::now();

        if (m_txQueue.empty())
            m_txPending.store(false, std::memory_order_relaxed);
        else
            sendSocketData();
    }
}

void EthStratumClient::onSSLShutdownCompleted(const boost::system::error_code& ec)
{
    (void)ec;
    clear_response_pleas();
    m_io_service.post(m_io_strand.wrap(boost::bind(&EthStratumClient::disconnect_finalize, this)));
}

void EthStratumClient::enqueue_response_plea()
{
    using namespace std::chrono;
    steady_clock::time_point response_plea_time = steady_clock::now();
    if (m_response_pleas_count++ == 0)
    {
        m_response_plea_older.store(
            response_plea_time.time_since_epoch(), std::memory_order_relaxed);
    }
    m_response_plea_times.push(response_plea_time);
}

std::chrono::milliseconds EthStratumClient::dequeue_response_plea()
{
    using namespace std::chrono;

    steady_clock::time_point response_plea_time(
        m_response_plea_older.load(std::memory_order_relaxed));
    milliseconds response_delay_ms =
        duration_cast<milliseconds>(steady_clock::now() - response_plea_time);

    if (m_response_plea_times.pop(response_plea_time))
    {
        m_response_plea_older.store(
            response_plea_time.time_since_epoch(), std::memory_order_relaxed);
    }
    if (m_response_pleas_count.load(std::memory_order_relaxed) > 0)
    {
        m_response_pleas_count--;
        return response_delay_ms;
    }
    else
    {
        return milliseconds(0);
    }
}

void EthStratumClient::clear_response_pleas()
{
    using namespace std::chrono;
    steady_clock::time_point response_plea_time;
    m_response_pleas_count.store(0, std::memory_order_relaxed);
    while (m_response_plea_times.pop(response_plea_time))
    {
    };
    m_response_plea_older.store(((steady_clock::time_point)steady_clock::now()).time_since_epoch(),
        std::memory_order_relaxed);
}
