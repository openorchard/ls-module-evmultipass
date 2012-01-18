<?php
/**
 * evMultiPass_Module.php
 *
 *
 *  
 *	@author Joe Richardson
 *  @license http://unlicense.org/ Released under the unlicense. 
 */


	class evMultiPass_Module extends Core_ModuleBase
	{

		/**
		 * Creates the module information object
		 * @return Core_ModuleInfo
		 */
		protected function createModuleInfo()
		{
			return new Core_ModuleInfo(
				"EHLO's MultiPass",
				"This MultiPass enables multiple authentication protocols to be handled for customer authentication. Each protocol must also be loaded in a separate module.",
				"EHLOVader" );
		}

	}
