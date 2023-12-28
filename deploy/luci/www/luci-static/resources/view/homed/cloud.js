'use strict';'require view';'require fs';'require ui';var isReadonlyView=!L.hasViewPermission()||null;return view.extend({load:function(){return L.resolveDefault(fs.read('/etc/homed/homed-cloud.conf'),'');},handleSave:function(ev){var value=(document.querySelector('textarea').value||'');return fs.write('/etc/homed/homed-cloud.conf',value).then(function(rc){document.querySelector('textarea').value=value;ui.addNotification(null,E('p',_('Configuration have been succesfully saved!')),'info');}).catch(function(e){ui.addNotification(null,E('p',_('Unable to save configuration: %s').format(e.message)));});},render:function(configuration){return E([E('h2',_('HOMEd Cloud Service Configuration')),E('p',{'class':'cbi-section-descr'},_('Documentation can be found <a href="https://wiki.homed.dev/page/Cloud/Configuration" target="_blank">here</a>.')),E('p',{},E('textarea',{'style':'width:100%','rows':25,'disabled':isReadonlyView},[configuration!=null?configuration:'']))]);},handleSaveApply:null,handleReset:null});