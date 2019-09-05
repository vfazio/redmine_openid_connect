Redmine::Plugin.register :redmine_openid_connect do
  name 'Redmine Openid Connect plugin'
  author 'Alfonso Juan Dillera / Markus M. May'
  description 'OpenID Connect implementation for Redmine'
  version '0.9.4'
  url 'https://github.com/devopskube/redmine_openid_connect'
  author_url 'http://github.com/adillera'

  settings :default => { 'empty' => true }, partial: 'settings/redmine_openid_connect_settings'
end

unless Redmine::Plugin.installed?(:easy_extensions)
  require_relative 'after_init'
end
