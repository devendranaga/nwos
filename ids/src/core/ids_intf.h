#ifndef IDS_INTF_H
#define IDS_INTF_H

#include <string>
#include <memory>

#include "raw_socket.h"

namespace netos {

namespace ids {

class ids_intf {
	public:
		explicit ids_intf() = default;
		~ids_intf() = default;

		void initialize();

	private:
		const std::string ifname;
		std::shared_ptr<netos::lib::raw_socket> raw_sk_;
		void receive_thread();
};

}

}

#endif

