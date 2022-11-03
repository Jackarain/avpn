#include <boost/process.hpp>

#include "avpn/hook.hpp"

#include "utils/logging.hpp"

namespace bp = boost::process;

namespace avpn {
    
    int32_t run_hook(string cmd, map<string, string> env)
    {
        bp::environment env_ = boost::this_process::environment();
        for (auto &e : env)
            env_[e.first] = e.second;
        int ret = bp::system(cmd, bp::std_out > stdout, bp::std_err > stderr, env_);
        LOG_DBG << "run_hook: " << cmd << " ret: " << ret;
        return ret;
    }

}