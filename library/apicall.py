#!/usr/bin/python

from ansible.module_utils.basic import *

import json
import sys
import subprocess
import re
import urllib

try:
    import requests
except ImportError:
    print "Please install the python-requests module."
    sys.exit(-1)



class apicall(object):


	def __init__(self,module,apiparams,APILABEL):
		self.module=module
		self.APILABEL = APILABEL
		self.apiparams = apiparams

		#self.ID=None
		del module.params['api']

		self.name = module.params['name']

		self.method = module.params['method']
		del module.params['method']
	
		#self.state = module.params['state']
		#del module.params['state']

		self.sat = module.params['sat']
		del module.params['sat']

		self.cert = module.params['cert']
		del module.params['cert']

		self.USERNAME = module.params['username']
		del module.params['username']

		self.PASSWORD = module.params['password']
		del module.params['password']

		self.payload=dict()
		for i in module.params.keys():
			if module.params[i] != None and module.params[i] != "":
				self.payload[i]= module.params[i]

		self.methodfunctions={'GET': self.get_json, 'PUT': self.put_json, 'POST': self.post_json, 'DELETE': self.delete_json}


#############
	def callapi(self, name, args={}):
		if self.apiparams.get(name) == None:
			self.module.fail_json(msg="ERROR action %s unknown"%(name))
			
		url = self.apiparams[name]['url']
		method= self.apiparams[name]['method']

		params = self.getargs(self.apiparams[name]['args'])
		params.update(args)
		
		##this seems like a very inefficient way to do this...
		url=re.sub("^/api/(?=[^v2])","/api/v2/",url)
		for p in self.payload.keys():
			url=re.sub("/:%s(?=[/$]*)"%p,"/%s"%self.payload[p],url)

		r = self.methodfunctions[method]('https://'+self.sat+url,params)
		#if r.status_code >=400:
		#	return None

		jsn = r.json()
		#if self.method=="index":
		#	self.module.fail_json(msg="ERROR %s+%s+%s"%(name,r.url,'https://'+self.sat+url))

		if jsn.get('error'):
			self.module.fail_json(msg="ERROR %s %s"%(name,jsn['error']))
			return None
		else:
			if jsn.get('subtotal',1)==0:
				return None
			elif jsn.get('results'):
				return jsn['results']
			else:
				return jsn
	

	def getargs(self,argdict):
		results = dict()
		for i in argdict.keys():
			if type(argdict[i]) is dict:
				results[i]= self.getargs(argdict[i])
				if results[i]=={}:
					del results[i]
				#self.module.fail_json(msg="args=: %s -- %s -- %s"%(i,argdict[i],type(argdict[i])))
			else:
				if self.payload.get(i):
					results[i]=self.payload[i]
				elif argdict[i]==True:
					self.module.fail_json(msg="ERROR %s required for %s"%(i,self.APILABEL))
		return results


	def haschanged(self,results):
		mapping={'organizations': {'payload': 'organization_ids','field': 'id'},
					'domains': {'payload': 'domain_ids','field': 'id'},
					'locations': {'payload': 'location_ids','field': 'id'},
					'interfaces': {'payload': 'interface_ids','field': 'id'},
					'dhcp':  {'payload': 'dhcp_id','field': 'id'},
					'dns':  {'payload': 'dns_id','field': 'id'},
					'prior':  {'payload': 'prior_id','field': 'id'},
					'tftp':  {'payload': 'tftp_id','field': 'id'}}


		for r in results.keys():
			if type(results[r]) is dict:
				if mapping.get(r)==None or self.payload.get(mapping[r]['payload'])==None:
					continue
				rvalue=results[r][mapping[r]['field']]
				pvalue=self.payload[mapping[r]['payload']]
				#self.module.exit_json(changed=False, name="dict= %s!=%s "%(rvalue,pvalue))
				if rvalue!=pvalue:
					return True

			elif type(results[r]) is list:
				if mapping.get(r)==None or self.payload.get(mapping[r]['payload'])==None:
					continue
				rvalues=set()
				pvalues=set(self.payload[mapping[r]['payload']])
				for i in results[r]:
					rvalues.add(str(i[mapping[r]['field']]))

				if rvalues != pvalues:
					return True

			else:
				if mapping.get(r):
					pname=mapping[r]['payload']
				else:
					pname=r
				#if r == "tftp":
				#	self.module.exit_json(changed=False, name="%s!=%s update %s %s==%s"%(r,pname,mapping[r]['payload'],self.payload.get(pname),results[r]))
				if self.payload.get(pname):
					if results[r] == self.payload[pname]:
						continue
					else:
						#self.module.exit_json(changed=False, name="%s!=%s update"%(self.payload[r],results[r]))
						return True
		return False



	def execute(self):
		if self.method == "update":
			self.update()
		elif self.method == "index":
			ret=self.index()
			self.module.exit_json(changed=False, msg="%s %s"%(self.method,self.payload['name']), name="%s"%self.payload['name'], id="%s"%self.payload['id'], result=ret)
		elif self.method == "delete":
			ret=self.delete()
		else:
			ret=self.callapi(self.method)
			self.module.exit_json(changed=True, msg="%s %s"%(self.method,self.payload['name']), name="%s"%self.payload['name'], result=ret)


	def index(self):
		self.payload['id']=None
		r = self.callapi('index',{}) # {'search': 'name=%s'%(self.payload.get('name'))})

		if r != None:
			for i in r:
				if i['name'] == self.name:
					self.payload['id']=i['id']
					#self.ID=i['id']
					return i
		return None


	def delete(self):
		self.index()
		if self.payload['id'] == None:
			## do nothing, its already gone
			self.module.exit_json(changed=False, msg="%s: %s doesn't exist"%(self.APILABEL, self.payload['name']))
		else:
			##exists delete it.
			self.callapi('destroy')
			#self.module.exit_json(changed=True, name="%s removed"%(self.payload['name']))
			self.module.exit_json(changed=True, msg="%s: %s removed"%(self.APILABEL,self.payload['name']), name="%s"%self.payload['name'], id="%s"%self.payload['id'])


	def update(self):
		self.index()

		if self.payload['id'] == None:
			## need to create it
			ret=self.callapi('create')
			self.module.exit_json(changed=True, msg="%s created"%(self.payload['name']), name="%s"%ret.get('name'), id="%s"%ret.get('id'),result=ret)
		elif self.payload['id'] != None:
			## check if it needs updating
			ret = self.callapi('show')
			if self.haschanged(ret):
				ret=self.callapi('update')
				self.module.exit_json(changed=True, msg="%s updated"%(self.payload['name']), name="%s"%ret['name'], id="%s"%ret.get('id'),result=ret)
			self.module.exit_json(changed=False, msg="%s hasn't changed"%(self.payload['name']), name="%s"%(self.payload['name']),id="%s"%(self.payload['id']),result=ret)
		else:
			self.module.fail_json(msg="ERROR failed to retrieve %s"%(self.payload.get('name')))


	def delete_json(self,url,json_data):
 		"""
		Performs a DELETE using the passed URL location
		"""

		if self.module.check_mode:
			self.module.exit_json(changed=False, name="%s %s would be deleted"%(self.APILABEL, self.name))
		try:
			result = requests.delete(url, verify=self.cert, auth=(self.USERNAME, self.PASSWORD))
		except Exception,e:
			self.module.fail_json(msg="ERROR DELETE (%s+%s+%s+%s+%s) %s"%(url,self.cert,self.USERNAME, self.PASSWORD, json_data,e))
		return result


	def get_json(self,url,data):
 		"""
		Performs a GET using the passed URL location
		"""
		#self.module.fail_json(msg="2ERROR GET (%s+%s+%s+%s)"%(url,self.USERNAME, self.PASSWORD, data))
		query=""
		for k,v in data.iteritems():
			query += urllib.quote(k.strip()) + "=" + urllib.quote(str(v).strip()) +"&"
		result = requests.get(url, verify=self.cert, auth=(self.USERNAME, self.PASSWORD),params=query[:-1])
		#if self.method=="index":
		#	self.module.fail_json(msg="2ERROR GET (%s+%s+%s+%s+%s) %s "%(url,result.url,self.USERNAME, self.PASSWORD, data,result.json()))
		return result


	def post_json(self,url, data):
		"""
		Performs a POST and passes the data to the URL location
		"""
		if self.module.check_mode:
			self.module.exit_json(changed=False, name="%s %s would be created"%(self.APILABEL, self.name))

		#self.module.exit_json(changed=False, name="POST %s +%s+ would be created: %s  %s"%(self.APILABEL, self.payload['id'], url,json.dumps(data)))
		#self.module.fail_json(msg="2ERROR GET (%s+%s+%s) %s "%(url,self.USERNAME, self.PASSWORD, data))
		POST_HEADERS = {'Content-Type': 'application/json'}
		result = requests.post(
			url,
			data=json.dumps(data),
			verify=self.cert,
			auth=(self.USERNAME, self.PASSWORD),
			headers=POST_HEADERS)

		#self.module.exit_json(changed=True, name="%s +%s+: %s"%(url, data, result.text))
		return result


	def put_json(self,url, data):
		"""
		Performs a PUT and passes the data to the URL location
		"""
		#self.results="%s %% PUT"%(self.results)

		if self.module.check_mode:
			self.module.exit_json(changed=False, name="%s %s would be updated"%(self.APILABEL, self.name))

		#self.module.exit_json(changed=False, name="PUT %s +%s+ would be updated: %s  %s"%(self.APILABEL, self.payload['id'], url,json.dumps(data)))
		PUT_HEADERS = {'Content-Type': 'application/json'}
		result = requests.put(
			url,
			data=json.dumps(data),
			verify=self.cert,
			auth=(self.USERNAME, self.PASSWORD),
			headers=PUT_HEADERS)

		#self.module.exit_json(changed=True, name="%s +%s+: %s"%(url, data, result.text))
		return result



def main():

	### some default values
	USERNAME = "admin"
	PASSWORD = "password"
	API_CHOICES=['content_views',  'common_parameters',  'compute_resources',  'parameters',  'systems',  'gpg_keys',  'puppetclasses',  'repositories',  'external_usergroups',  'hosts',  'operating_systems',  'filters',  'hostgroups',  'override_values',  'ptables',  'content_view_filters',  'images',  'usergroups',  'models',  'registries',  'interfaces',  'os_default_templates',  'config_templates',  'smart_proxies',  'lifecycle_environments',  'compute_profiles',  'products',  'domains',  'environments',  'bookmarks',  'content_view_puppet_modules',  'discovered_hosts',  'sync_plans',  'content_view_filter_rules',  'realms',  'organizations',  'smart_variables',  'roles',  'activation_keys',  'locations',  'discovery_rules',  'auth_source_ldaps',  'host_collections',  'media',  'subnets',  'config_groups',  'users',  'architectures','repository_sets']

	### we have some args that apply to all api calls
	args= {
		"sat":		dict(required=False, default=os.uname()[1]),
		"cert":		dict(required=False, default='/etc/pki/katello/certs/katello-default-ca-stripped.crt'),
		"username":	dict(required=False, default=USERNAME),
		"password":	dict(required=False, default=PASSWORD),
		"method":	dict(required=False, default="update"),
		"api":		dict(required=True, choices=API_CHOICES),
		"name":		dict(required=True),
	}

	### pre-process the arguments to get the api call we're makng so we can check the arguments for it as we create the AnsibleModule object
	args_file = sys.argv[0]
	args_data = file(args_file).read()
	arguments= args_data.split("\n")
	for arg in arguments:
		if "MODULE_ARGS" in arg:
			(a,b)=arg.split("=",1)
			t = {k:v.strip('"') for k,v in re.findall(r'(\S+)=(".*?"|\S+)', b.strip(" '"))}
			APILABEL=t.get('api')		
			break


	### read the appropriate api json file
	apijsondata=dict()
	try:
		fd=open("/var/lib/foreman/public/apipie-cache/apidoc/v2/%s.json"%APILABEL,"r")
		apijsondata = json.load(fd)
	except Exception, e:
		print json.dumps({
			"failed": True,
			"msg" :"ERROR opening %s.json file: %s"%(APILABEL,e)
		})
		

	resource = apijsondata["docs"]["resources"][0]
	apiparams = dict()
	for m in resource['methods']:
		if m.get('deprecated')==True:
			continue

		name=m['name']
		#print "  %s"%(m['name'])
		if apiparams.get(name):
			continue

		apiparams[name]=dict()
		apiparams[name]['method']= m['apis'][0]['http_method']
		apiparams[name]['url']= m['apis'][0]['api_url']

		apiparams[name]['args']=dict()
		for p in m['params']:
			if  p['expected_type'] == "hash":
				apiparams[name]['args'][p['name']]=dict()
				for pp in p.get('params',[]):	
					apiparams[name]['args'][p['name']][pp['name']] = pp['required']
			else:
				apiparams[name]['args'][p['name']]= p['required']

	#print json.dumps({
	#		"failed" : True,
	#		"msg"    : "args %s"%(json.dumps(args))
	#	})
	#sys.exit(0)

	### now we can create the obj with the right arguement spec
	module = AnsibleModule(
		argument_spec = args,
		supports_check_mode=True,
		check_invalid_arguments=False,
		)	
	#if APILABEL=="subnets":
	#	print json.dumps({
	#			"failed" : True,
	#			"msg"    : "args %s++%s"%(json.dumps(module.params),apiparams)
	#		})
	#	sys.exit(0)

	ansible_sat = apicall(module,apiparams,APILABEL)

	#ansible_sat.run()
	ansible_sat.execute()
	


if __name__ == '__main__':
    main()

