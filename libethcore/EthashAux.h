/*
    This file is part of ethminer.

    ethminer is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ethminer is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ethminer.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <libdevcore/Common.h>
#include <libdevcore/Exceptions.h>
#include <libdevcore/Worker.h>

#include <ethash/ethash.hpp>
#include <memory>
#include <map>


#define OFF_CYCLE_LEN  8192	    	 //8192  2080
#define SKIP_CYCLE_LEN 2048     	//2048 520


namespace dev
{
namespace eth
{
struct Result
{
    h256 value;
    h256 mixHash;
};

class EthashAux
{
public:
    static Result eval(int epoch, h256 const& _headerHash, uint64_t _nonce) noexcept;
};

struct EpochContext
{
    int epochNumber;
    int lightNumItems;
    size_t lightSize;
    const ethash_hash512* lightCache;
    int dagNumItems;
    uint64_t dagSize;
};

class true_dataset
{
public:
    true_dataset(int l){
        if (l > 0) {
            dataset = std::make_shared<uint64_t>(new uint64_t[l],[](uint64_t* p){ if(p){delete [] p;} });
            len = l;   
        }
    }
    true_dataset(const true_dataset& tt) {
        dataset = tt.dataset;
        seed_hash = tt.seed_hash;
        len = tt.len;
    }
    // true_dataset()
    ~true_dataset() {
    }
    void make(uint8_t seeds[OFF_CYCLE_LEN + SKIP_CYCLE_LEN][16]) {
        // init dataset for spec seeds
        uint64_t *tmp = (uint64_t*)dataset.get();
    }
    void init(){
        uint64_t *tmp = (uint64_t*)dataset.get();
    }
    std::shared_ptr<uint64_t> dataset;
	std::string     seed_hash;
	int 	        len;
};

struct WorkPackage
{
    WorkPackage() = default;

    explicit operator bool() const { return header != h256(); }

    std::string job;  // Job identifier can be anything. Not necessarily a hash

    h256 boundary;      // 0-15: block target;16-31:fruit target
    h256 fruitBoundary; // fruit target
    h256 header;  ///< When h256() means "pause until notified a new work package is available".
    h256 seed;

    int epoch = -1;
    int block = -1;

    uint64_t startNonce = 0;
    uint16_t exSizeBytes = 0;

    std::string algo = "minerva";

    std::shared_ptr<true_dataset> ds;
};

struct Solution
{
    uint64_t nonce;                                // Solution found nonce
    h256 mixHash;                                  // Mix hash
    WorkPackage work;                              // WorkPackage this solution refers to
    std::chrono::steady_clock::time_point tstamp;  // Timestamp of found solution
    unsigned midx;                                 // Originating miner Id
};



class dataset_mgr 
{
public:
    dataset_mgr(){
        sum = 5;
    }
    ~dataset_mgr(){
        
    }
    void init(int len) {
        true_dataset first(len);
        first.init();
        set_dataset(&first);
    }
    std::shared_ptr<true_dataset> get_dataset(std::string &seed_hash) {
        dev::Guard g(cs);
        auto it = m_ds.find(seed_hash);
        if (it == m_ds.end()) {
            return nullptr;
        }
        return it->second;
    }
    void set_dataset(true_dataset *ds) {
        dev::Guard g(cs);
        auto it = m_ds.find(ds->seed_hash);
        if (it == m_ds.end()) {
            if (m_ds.size() >= sum) {
                m_ds.erase(m_ds.begin());       // ????
            }
            std::shared_ptr<true_dataset> sp(*ds);
            m_ds[ds.seed_hash] = sp;
        }
    }
    bool has_dataset(std::string &seed_hash) {
        dev::Guard g(cs);
        auto it = m_ds.find(seed_hash);
        if (it == m_ds.end()) {
            return false;
        }
        return true;
    }

private:
    std::map<std::string,std::shared_ptr<true_dataset>> m_ds;
    dev::Mutex cs;
    int sum;
};

}  // namespace eth
}  // namespace dev
