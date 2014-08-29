s2e = {
	kleeArgs = {
	-- Run each state for at least 30 second before
	-- switching to the other:
	"--use-batching-search=true", "--batch-time=30.0"
	}
}


plugins = {
	-- Enable a plugin that handles S2E custom opcode
	"BaseInstructions",
	"SimpleBundlePlugin"
}
pluginsConfig = {

}
pluginsConfig.BaseInstructions ={
--	so_path = "/home/wb/work/workspace/prophet/publicbundles/publicbundle.so",--如果这个参数不为空，且文件存在，那么系统将首先将库文件加载进内存，并调用其init_bundle函数
	--如果是卸载这个插件，则不会将其移除内存，而只是调用其disable_bundle函数
}
pluginsConfig.SimpleBundlePlugin ={
	so_path = "/home/wb/work/workspace/prophet/publicbundles/publicbundle.so",--如果这个参数不为空，且文件存在，那么系统将首先将库文件加载进内存，并调用其init_bundle函数
	--如果是卸载这个插件，则不会将其移除内存，而只是调用其disable_bundle函数
}