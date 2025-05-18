#include "source/common/common/thread.h"
#include "source/exe/main_common.h"

#include "absl/debugging/symbolize.h"
#include "absl/strings/str_join.h"

// NOLINT(namespace-envoy)
int main(int argc, char** argv) {
  // Initialize the symbolizer to get better stack traces in error messages
  absl::InitializeSymbolizer(argv[0]);

  // Create a vector of args
  std::vector<std::string> args(argv, argv + argc);

  // Add our kTLS extension
  args.push_back("--enable-core-dump");

  // Create MainCommon and run
  try {
    Envoy::MainCommon main_common(argc, argv);
    Envoy::Thread::threadFactoryForTest().createThread([&main_common]() { main_common.run(); });

    // Wait for a signal to exit
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGHUP);
    sigprocmask(SIG_BLOCK, &mask, nullptr);

    int sig;
    sigwait(&mask, &sig);

    return main_common.shutdown() ? 0 : 1;
  } catch (const Envoy::NoServingException& e) {
    return 0;
  } catch (const Envoy::MalformedArgvException& e) {
    std::cerr << e.what() << std::endl;
    return 1;
  } catch (const Envoy::EnvoyException& e) {
    std::cerr << e.what() << std::endl;
    return 1;
  }
}
