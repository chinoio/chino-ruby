require "test/unit"
require_relative "../lib/chino_ruby"

class SDKTest < Test::Unit::TestCase
   
   def setup
       @RAILS_ROOT = File.join(File.dirname(__FILE__), '../')
       @KEYS = YAML::load(File.open("#{@RAILS_ROOT}/config-chino.yml"))
       
       @DEVELOPMENT_KEYS = @KEYS['development_old']
       #@DEVELOPMENT_KEYS = @KEYS['development']
       
       @client = ChinoAPI.new(@DEVELOPMENT_KEYS['customer_id'], @DEVELOPMENT_KEYS['customer_key'], @DEVELOPMENT_KEYS['url'])
       @success = "success"
       #active_all
       #delete_all
   end
   
   def test_applications
       description = "test_application_ruby"
       description_updated = "test_application_ruby_updated"
       app = @client.applications.create_application(description, "password", "")
       assert_equal(app.app_name, description)
       assert_not_equal(app.app_id, "")
       app = @client.applications.get_application(app.app_id)
       assert_equal(app.app_name, description)
       assert_not_equal(app.app_id, "")
       app = @client.applications.update_application(app.app_id, description_updated, "password", "")
       assert_equal(app.app_name, description_updated)
       assert_not_equal(app.app_id, "")
       apps = @client.applications.list_applications
       apps.applications.each do |a|
           assert_not_equal(app.app_id, "")
           assert_not_equal(app.app_name, "")
       end
       apps = @client.applications.list_applications(2, 2)
       apps.applications.each do |a|
           assert_not_equal(app.app_id, "")
       end
       assert_equal(@client.applications.delete_application(app.app_id, true), @success)
   end
   
   def test_repositories
       description = "test repository ruby"
       description_updated = "test_repository_ruby_updated"
       repo = @client.repositories.create_repository(description)
       assert_equal(repo.description, description)
       assert_not_equal(repo.repository_id, "")
       
       repo = @client.repositories.update_repository(repo.repository_id, description_updated)
       assert_equal(repo.description, description_updated)
       assert_not_equal(repo.repository_id, "")
       
       repos = @client.repositories.list_repositories
       repos.repositories.each do |r|
           assert_not_equal(r.repository_id, "")
       end
       assert_equal(@client.repositories.delete_repository(repo.repository_id, true), @success)
   end
   
   def test_schemas
       description = "test_repository_ruby"
       repo = @client.repositories.create_repository(description)
       assert_equal(repo.description, description)
       assert_not_equal(repo.repository_id, "")
       
       fields = []
       fields.push(Field.new("string", "test_string", true))
       fields.push(Field.new("integer", "test_integer", true))
       fields.push(Field.new("blob", "test_blob", false))
       
       description = "test-schema-description-ruby"
       
       schema = @client.schemas.create_schema(repo.repository_id, description, fields)
       assert_equal(schema.description, description)
       assert_equal(schema.getFields.size, 3)
       assert_not_equal(schema.schema_id, description)
       
       schema = @client.schemas.get_schema(schema.schema_id)
       assert_equal(schema.description, description)
       assert_equal(schema.getFields.size, 3)
       assert_not_equal(schema.schema_id, description)
       
       
       description = "test-schema-description-ruby-updated"
       
       schema = @client.schemas.update_schema(schema.schema_id, description, fields)
       assert_equal(schema.description, description)
       assert_equal(schema.getFields.size, 3)
       assert_not_equal(schema.schema_id, description)
       
       schemas = @client.schemas.list_schemas(repo.repository_id)
       schemas.schemas.each do |s|
           assert_equal(s.description, description)
           assert_not_equal(s.schema_id, description)
       end
       assert_equal(@client.schemas.delete_schema(schema.schema_id, true), @success)
       assert_equal(@client.repositories.delete_repository(repo.repository_id, true), @success)
   end
   
   def test_documents
       description = "test_repository_ruby"
       repo = @client.repositories.create_repository(description)
       assert_equal(repo.description, description)
       assert_not_equal(repo.repository_id, "")
       
       fields = []
       fields.push(Field.new("string", "test_string", true))
       fields.push(Field.new("integer", "test_integer", true))
       fields.push(Field.new("blob", "test_blob", false))
       
       description = "test-schema-description-ruby"
       
       schema = @client.schemas.create_schema(repo.repository_id, description, fields)
       assert_equal(schema.description, description)
       assert_equal(schema.getFields.size, 3)
       assert_not_equal(schema.schema_id, description)
       
       content = Hash.new
       content["test_string"] = "sample value ruby"
       content["test_integer"] = 123
       
       doc = @client.documents.create_document(schema.schema_id, content)
       assert_not_equal(doc.document_id, "")
       
       doc = @client.documents.get_document(doc.document_id)
       assert_equal(doc.content['test_string'], "sample value ruby")
       assert_equal(doc.content['test_integer'], 123)
       assert_not_equal(doc.document_id, "")
       
       content["test_integer"] = 1233
       
       doc = @client.documents.update_document(doc.document_id, content)
       assert_not_equal(doc.document_id, "")
       
       doc = @client.documents.get_document(doc.document_id)
       assert_equal(doc.content['test_string'], "sample value ruby")
       assert_equal(doc.content['test_integer'], 1233)
       assert_not_equal(doc.document_id, "")
       
       docs = @client.documents.list_documents(schema.schema_id, true)
       docs.documents.each do |d|
           assert_not_equal(d.document_id, "")
       end
       
       docs = @client.documents.list_documents(schema.schema_id, false, 100, 0)
       docs.documents.each do |d|
           assert_not_equal(d.document_id, "")
       end
       
       assert_equal(@client.documents.delete_document(doc.document_id, true), @success)
       assert_equal(@client.schemas.delete_schema(schema.schema_id, true), @success)
       assert_equal(@client.repositories.delete_repository(repo.repository_id, true), @success)
   end
   
   def test_user_schemas
       description = "test-user-schema-description-ruby"
       description_updated = "test-user-schema-description-ruby-updated"
       fields = []
       fields.push(Field.new("string", "test_string", true))
       fields.push(Field.new("integer", "test_integer", true))
       
       u_schema = @client.user_schemas.create_user_schema(description, fields)
       assert_equal(u_schema.description, description)
       assert_equal(u_schema.getFields.size, 2)
       assert_not_equal(u_schema.user_schema_id, "")
       
       u_schema = @client.user_schemas.get_user_schema(u_schema.user_schema_id)
       assert_equal(u_schema.description, description)
       assert_equal(u_schema.getFields.size, 2)
       assert_not_equal(u_schema.user_schema_id, "")
       
       u_schema = @client.user_schemas.update_user_schema(u_schema.user_schema_id, description_updated, fields)
       assert_equal(u_schema.description, description_updated)
       assert_equal(u_schema.getFields.size, 2)
       assert_not_equal(u_schema.user_schema_id, "")
       
       schemas = @client.user_schemas.list_user_schemas
       schemas.user_schemas.each do |s|
           assert_not_equal(s.user_schema_id, "")
       end
       assert_equal(@client.user_schemas.delete_user_schema(u_schema.user_schema_id, true), @success)
   end
   
   def test_users
       description = "test-user-schema-description-ruby"
       fields = []
       fields.push(Field.new("string", "test_string", true))
       fields.push(Field.new("integer", "test_integer", true))
       
       u_schema = @client.user_schemas.create_user_schema(description, fields)
       assert_equal(u_schema.description, description)
       assert_equal(u_schema.getFields.size, 2)
       assert_not_equal(u_schema.user_schema_id, "")
       
       attributes = Hash.new
       attributes["test_string"] = "sample value ruby"
       attributes["test_integer"] = 123
       
       username = "testUsernameRuby"+rand(1..300).to_s
       
       usr = @client.users.create_user(u_schema.user_schema_id, username, "testPassword", attributes)
       assert_equal(usr.user_attributes['test_string'], "sample value ruby")
       assert_equal(usr.user_attributes['test_integer'], 123)
       assert_not_equal(usr.user_id, "")
       
       usr = @client.users.get_user(usr.user_id)
       assert_equal(usr.user_attributes['test_string'], "sample value ruby")
       assert_equal(usr.user_attributes['test_integer'], 123)
       assert_not_equal(usr.user_id, "")
       
       attributes["test_integer"] = 1233
       
       usr = @client.users.update_user(usr.user_id, username, "testPassword", attributes)
       assert_equal(usr.user_attributes['test_string'], "sample value ruby")
       assert_equal(usr.user_attributes['test_integer'], 1233)
       assert_not_equal(usr.user_id, "")
       
       attributes = Hash.new
       attributes["test_integer"] = 666
       
       usr = @client.users.update_user_partial(usr.user_id, attributes)
       assert_equal(usr.user_attributes['test_string'], "sample value ruby")
       assert_equal(usr.user_attributes['test_integer'], 666)
       assert_not_equal(usr.user_id, "")
       
       users = @client.users.list_users(u_schema.user_schema_id)
       users.users.each do |u|
           assert_not_equal(u.user_id, "")
       end
       assert_equal(@client.users.delete_user(usr.user_id, true), @success)
       assert_equal(@client.user_schemas.delete_user_schema(u_schema.user_schema_id, true), @success)
   end
   
   def test_groups
       description = "test-user-schema-description-ruby"
       fields = []
       fields.push(Field.new("string", "test_string", true))
       fields.push(Field.new("integer", "test_integer", true))
       
       u_schema = @client.user_schemas.create_user_schema(description, fields)
       assert_equal(u_schema.description, description)
       assert_equal(u_schema.getFields.size, 2)
       assert_not_equal(u_schema.user_schema_id, "")
       
       attributes = Hash.new
       attributes["test_string"] = "sample value ruby"
       attributes["test_integer"] = 123
       
       username = "testUsernameRuby"+rand(1..300).to_s
       
       usr = @client.users.create_user(u_schema.user_schema_id, username, "testPassword", attributes)
       assert_equal(usr.user_attributes['test_string'], "sample value ruby")
       assert_equal(usr.user_attributes['test_integer'], 123)
       assert_not_equal(usr.user_id, "")
       
       group_name = "testGroup"+rand(1..300).to_s
       
       group = @client.groups.create_group(group_name, attributes)
       assert_equal(group.group_attributes['test_string'], "sample value ruby")
       assert_equal(group.group_attributes['test_integer'], 123)
       assert_not_equal(group.group_id, "")
       
       group = @client.groups.get_group(group.group_id)
       assert_equal(group.group_attributes['test_string'], "sample value ruby")
       assert_equal(group.group_attributes['test_integer'], 123)
       assert_not_equal(group.group_id, "")
       
       attributes["test_string"] = "sample value ruby"
       attributes["test_integer"] = 1233
       
       group = @client.groups.update_group(group.group_id, group_name, attributes)
       assert_equal(group.group_attributes['test_string'], "sample value ruby")
       assert_equal(group.group_attributes['test_integer'], 1233)
       assert_not_equal(group.group_id, "")
       
       groups = @client.groups.list_groups(100, 0)
       groups.groups.each do |g|
           assert_not_equal(g.group_id, "")
       end
       
       assert_equal(@client.groups.add_user_to_group(usr.user_id, group.group_id), @success)
       assert_equal(@client.groups.add_user_schema_to_group(u_schema.user_schema_id, group.group_id), @success)
       
       usr = @client.users.get_user(usr.user_id)
       assert_not_equal(usr.user_id, "")
       assert_equal(usr.groups.size, 1)
       
       assert_equal(@client.groups.remove_user_from_group(usr.user_id, group.group_id), @success)
       assert_equal(@client.groups.remove_user_schema_from_group(u_schema.user_schema_id, group.group_id), @success)
       
       usr = @client.users.get_user(usr.user_id)
       assert_not_equal(usr.user_id, "")
       assert_equal(usr.groups.size, 0)
       
       assert_equal(@client.groups.delete_group(group.group_id, true), @success)
       assert_equal(@client.users.delete_user(usr.user_id, true), @success)
       assert_equal(@client.user_schemas.delete_user_schema(u_schema.user_schema_id, true), @success)
   end
   
   def test_collections
       description = "test_repository_ruby"
       repo = @client.repositories.create_repository(description)
       assert_equal(repo.description, description)
       assert_not_equal(repo.repository_id, "")
       
       fields = []
       fields.push(Field.new("string", "test_string", true))
       fields.push(Field.new("integer", "test_integer", true))
       fields.push(Field.new("blob", "test_blob", false))
       
       description = "test-schema-description-ruby"
       
       schema = @client.schemas.create_schema(repo.repository_id, description, fields)
       assert_equal(schema.description, description)
       assert_equal(schema.getFields.size, 3)
       assert_not_equal(schema.schema_id, "")
       
       content = Hash.new
       content["test_string"] = "sample value ruby"
       content["test_integer"] = 123
       
       doc = @client.documents.create_document(schema.schema_id, content)
       assert_not_equal(doc.document_id, "")
       
       description = "test-decription-ruby"+rand(1..300).to_s
       
       col = @client.collections.create_collection(description)
       assert_not_equal(col.collection_id, "")
       assert_equal(col.name, description)
       
       col = @client.collections.update_collection(col.collection_id, description+"-updated")
       assert_not_equal(col.collection_id, "")
       assert_equal(col.name, description+"-updated")
       
       cols = @client.collections.list_collections()
       cols.collections.each do |c|
           assert_not_equal(c.collection_id, "")
       end
       
       assert_equal(@client.collections.add_document(doc.document_id, col.collection_id), @success)
       
       docs = @client.collections.list_documents(col.collection_id)
       assert_equal(docs.documents.size, 1)
       docs.documents.each do |d|
           assert_not_equal(d.document_id, "")
       end
       
       assert_equal(@client.collections.remove_document(doc.document_id, col.collection_id), @success)
       
       docs = @client.collections.list_documents(col.collection_id)
       assert_equal(docs.documents.size, 0)
       
       assert_equal(@client.collections.delete_collection(col.collection_id, true), @success)
       assert_equal(@client.documents.delete_document(doc.document_id, true), @success)
       assert_equal(@client.schemas.delete_schema(schema.schema_id, true), @success)
       assert_equal(@client.repositories.delete_repository(repo.repository_id, true), @success)
   end
   
   def test_permissions
       description = "test_repository_ruby"
       repo = @client.repositories.create_repository(description)
       assert_equal(repo.description, description)
       assert_not_equal(repo.repository_id, "")
       
       fields = []
       fields.push(Field.new("string", "test_string", true))
       fields.push(Field.new("integer", "test_integer", true))
       fields.push(Field.new("blob", "test_blob", false))
       
       description = "test-schema-description-ruby"
       
       schema = @client.schemas.create_schema(repo.repository_id, description, fields)
       assert_equal(schema.description, description)
       assert_equal(schema.getFields.size, 3)
       assert_not_equal(schema.schema_id, "")
       
       content = Hash.new
       content["test_string"] = "sample value ruby"
       content["test_integer"] = 123
       
       doc = @client.documents.create_document(schema.schema_id, content)
       assert_not_equal(doc.document_id, "")
       
       description = "test-user-schema-description-ruby"
       fields = []
       fields.push(Field.new("string", "test_string", true))
       fields.push(Field.new("integer", "test_integer", true))
       
       u_schema = @client.user_schemas.create_user_schema(description, fields)
       assert_equal(u_schema.description, description)
       assert_equal(u_schema.getFields.size, 2)
       assert_not_equal(u_schema.user_schema_id, "")
       
       attributes = Hash.new
       attributes["test_string"] = "sample value ruby"
       attributes["test_integer"] = 123
       
       username = "testUsernameRuby"+rand(1..300).to_s
       
       usr = @client.users.create_user(u_schema.user_schema_id, username, "testPassword", attributes)
       assert_equal(usr.user_attributes['test_string'], "sample value ruby")
       assert_equal(usr.user_attributes['test_integer'], 123)
       assert_not_equal(usr.user_id, "")
       
       assert_equal(@client.permissions.permissions_on_resources("grant", "repositories", "users", usr.user_id, ["R", "U"], ["R"]), @success)
       
       perms = @client.permissions.read_permissions_of_a_user(usr.user_id)
       assert_equal(perms.permissions.size, 1)
       perms.permissions.each do |p|
           assert_equal(p.permission['Manage'], ["R", "U"])
       end
       
       assert_equal(@client.permissions.permissions_on_a_resource_children_created_document("grant", "schemas", schema.schema_id, "documents", "users", usr.user_id, ["R", "U", "C"], [], ["R", "U", "D"], ["R"]), @success)
       
       perms = @client.permissions.read_permissions_of_a_user(usr.user_id)
       assert_equal(perms.permissions.size, 2)
       perms.permissions.each do |p|
           if not p.permission['created_document']==nil
               assert_equal(p.permission['created_document']['Manage'], ["R", "U", "D"])
           end
       end
       assert_equal(@client.users.delete_user(usr.user_id, true), @success)
       assert_equal(@client.user_schemas.delete_user_schema(u_schema.user_schema_id, true), @success)
       assert_equal(@client.documents.delete_document(doc.document_id, true), @success)
       assert_equal(@client.schemas.delete_schema(schema.schema_id, true), @success)
       assert_equal(@client.repositories.delete_repository(repo.repository_id, true), @success)
   end
   
   def test_search
       description = "test_repository_ruby"
       repo = @client.repositories.create_repository(description)
       assert_equal(repo.description, description)
       assert_not_equal(repo.repository_id, "")
       
       fields = []
       fields.push(Field.new("string", "test_string", true))
       fields.push(Field.new("integer", "test_integer", true))
       fields.push(Field.new("blob", "test_blob", false))
       
       description = "test-schema-description-ruby"
       
       schema = @client.schemas.create_schema(repo.repository_id, description, fields)
       assert_equal(schema.description, description)
       assert_equal(schema.getFields.size, 3)
       assert_not_equal(schema.schema_id, "")
       
       content = Hash.new
       content["test_string"] = "sample value ruby"
       content["test_integer"] = 1233
       
       doc = @client.documents.create_document(schema.schema_id, content)
       assert_not_equal(doc.document_id, "")
       
       description = "test-user-schema-description-ruby"
       fields = []
       fields.push(Field.new("string", "test_string", true))
       fields.push(Field.new("integer", "test_integer", true))
       
       u_schema = @client.user_schemas.create_user_schema(description, fields)
       assert_equal(u_schema.description, description)
       assert_equal(u_schema.getFields.size, 2)
       assert_not_equal(u_schema.user_schema_id, "")
       
       attributes = Hash.new
       attributes["test_string"] = "sample value ruby"
       attributes["test_integer"] = 666
       
       username = "testUsernameRuby"+rand(1..300).to_s
       
       usr = @client.users.create_user(u_schema.user_schema_id, username, "testPassword", attributes)
       assert_equal(usr.user_attributes['test_string'], "sample value ruby")
       assert_equal(usr.user_attributes['test_integer'], 666)
       assert_not_equal(usr.user_id, "")
       
       sleep(3)
       
       sort = []
       sort.push(SortOption.new("test_string", "asc"))
       
       filter = []
       filter.push(FilterOption.new("test_string", "eq", "sample value ruby"))
       filter.push(FilterOption.new("test_integer", "eq", 1233))
       
       docs = @client.search.search_documents(schema.schema_id, "FULL_CONTENT", "and", sort, filter)
       assert_equal(docs.documents.size, 1)
       docs.documents.each do |d|
           assert_equal(d.content['test_string'], "sample value ruby")
           assert_equal(d.content['test_integer'], 1233)
       end
       
       sort = []
       sort.push(SortOption.new("test_string", "asc"))
       
       filter = []
       filter.push(FilterOption.new("test_string", "eq", "sample value ruby"))
       filter.push(FilterOption.new("test_integer", "eq", 666))
       
       users = @client.search.search_users(u_schema.user_schema_id, "FULL_CONTENT", "and", sort, filter)
       assert_equal(users.users.size, 1)
       users.users.each do |u|
           assert_equal(u.user_attributes['test_string'], "sample value ruby")
           assert_equal(u.user_attributes['test_integer'], 666)
       end

        assert_equal(@client.users.delete_user(usr.user_id, true), @success)
        assert_equal(@client.user_schemas.delete_user_schema(u_schema.user_schema_id, true), @success)
        assert_equal(@client.documents.delete_document(doc.document_id, true), @success)
        assert_equal(@client.schemas.delete_schema(schema.schema_id, true), @success)
        assert_equal(@client.repositories.delete_repository(repo.repository_id, true), @success)
   end
   
   def test_blobs
       description = "test_repository_ruby"
       repo = @client.repositories.create_repository(description)
       assert_equal(repo.description, description)
       assert_not_equal(repo.repository_id, "")
       
       fields = []
       fields.push(Field.new("string", "test_string", true))
       fields.push(Field.new("integer", "test_integer", true))
       fields.push(Field.new("blob", "test_blob", false))
       
       description = "test-schema-description-ruby"
       
       schema = @client.schemas.create_schema(repo.repository_id, description, fields)
       assert_equal(schema.description, description)
       assert_equal(schema.getFields.size, 3)
       assert_not_equal(schema.schema_id, "")
       
       content = Hash.new
       content["test_string"] = "sample value ruby"
       content["test_integer"] = 1233
       
       doc = @client.documents.create_document(schema.schema_id, content)
       assert_not_equal(doc.document_id, "")
       
       filename = "Chino.io-eBook-Health-App-Compliance.pdf"
       path = "test/testfiles/"
       
       blob = @client.blobs.upload_blob(path, filename, doc.document_id, "test_blob")
       assert_not_equal(blob.document_id, "")
       assert_not_equal(blob.blob_id, "")
       
       output_path = "test/testfiles/output/"
       
       getBlob = @client.blobs.get(blob.blob_id, output_path)
       assert_not_equal(getBlob.blob_id, "")
       assert_equal(getBlob.path, output_path)
       assert_equal(getBlob.filename, filename)
       #assert_equal(blob.size, getBlob.size)
       assert_equal(blob.sha1, getBlob.sha1)
       assert_equal(blob.md5, getBlob.md5)
       
       assert_equal(@client.blobs.delete_blob(blob.blob_id, true), @success)
       assert_equal(@client.documents.delete_document(doc.document_id, true), @success)
       assert_equal(@client.schemas.delete_schema(schema.schema_id, true), @success)
       assert_equal(@client.repositories.delete_repository(repo.repository_id, true), @success)
   end
   
   def test_auth
       description = "test-user-schema-description-ruby"
       fields = []
       fields.push(Field.new("string", "test_string", true))
       fields.push(Field.new("integer", "test_integer", true))
       
       u_schema = @client.user_schemas.create_user_schema(description, fields)
       assert_equal(u_schema.description, description)
       assert_equal(u_schema.getFields.size, 2)
       assert_not_equal(u_schema.user_schema_id, "")
       
       attributes = Hash.new
       attributes["test_string"] = "sample value ruby"
       attributes["test_integer"] = 123
       
       username = "testUsernameRuby"+rand(1..300).to_s
       
       usr = @client.users.create_user(u_schema.user_schema_id, username, "testPassword", attributes)
       assert_equal(usr.user_attributes['test_string'], "sample value ruby")
       assert_equal(usr.user_attributes['test_integer'], 123)
       assert_not_equal(usr.user_id, "")
       
       description = "test_application_ruby"
       
       app = @client.applications.create_application(description, "password", "")
       assert_equal(app.app_name, description)
       assert_not_equal(app.app_id, "")
       
       l_usr = @client.auth.login_password(username, "testPassword", app.app_id, app.app_secret)
       assert_not_equal(l_usr.access_token, "")
       assert_not_equal(l_usr.token_type, "")
       assert_not_equal(l_usr.refresh_token, "")
       
       l_usr = @client.auth.refresh_token(l_usr.refresh_token, app.app_id, app.app_secret)
       assert_not_equal(l_usr.access_token, "")
       assert_not_equal(l_usr.token_type, "")

       @client = ChinoAPI.new("Bearer ", l_usr.access_token, @DEVELOPMENT_KEYS['url'])
       
       assert_equal(@client.auth.logout(l_usr.access_token, app.app_id, app.app_secret), @success)
       
       @client = ChinoAPI.new(@DEVELOPMENT_KEYS['customer_id'], @DEVELOPMENT_KEYS['customer_key'], @DEVELOPMENT_KEYS['url'])

       assert_equal(@client.users.delete_user(usr.user_id, true), @success)
       assert_equal(@client.user_schemas.delete_user_schema(u_schema.user_schema_id, true), @success)
   end
   
   def test_errors
       assert_raise ArgumentError do
           @client.applications.create_application(12, "password", "")
       end
       app = @client.applications.create_application("test-app-ruby", "password", "")
       assert_raise ChinoAuthError do
           @client.auth.login_password("wrong-username", "testPassword", app.app_id, app.app_secret)
       end
       assert_raise ChinoError do
           @client.applications.get_application("wrong-id")
       end
       assert_raise URI::InvalidURIError do
           @client.applications.get_application("wrong id")
       end
   end
   
   def delete_all
       schemas = @client.user_schemas.list_user_schemas
       schemas.user_schemas.each do |s|
           users = @client.users.list_users(s.user_schema_id)
           users.users.each do |u|
               puts @client.users.delete_user(u.user_id, true)
           end
           puts @client.user_schemas.delete_user_schema(s.user_schema_id, true)
       end
       
       repos = @client.repositories.list_repositories
       repos.repositories.each do |r|
           schemas = @client.schemas.list_schemas(r.repository_id)
           schemas.schemas.each do |s|
               docs = @client.documents.list_documents(s.schema_id, true)
               docs.documents.each do |d|
                   puts @client.documents.delete_document(d.document_id, true)
               end
               puts @client.schemas.delete_schema(s.schema_id, true)
           end
           puts @client.repositories.delete_repository(r.repository_id, true)
       end
       
       cols = @client.collections.list_collections
       cols.collections.each do |c|
           puts @client.collections.delete_collection(c.collection_id, true)
       end
       
       groups = @client.groups.list_groups
       groups.groups.each do |g|
           puts @client.groups.delete_group(g.group_id, true)
       end
   end
   
   def active_all
       repos = @client.repositories.list_repositories
       repos.repositories.each do |r|
           @client.repositories.update_repository(r.repository_id, r.description, true)
           schemas = @client.schemas.list_schemas(r.repository_id)
           schemas.schemas.each do |s|
               @client.schemas.update_schema(s.schema_id, s.description, s.getFields, true)
               docs = @client.documents.list_documents(s.schema_id, true)
               docs.documents.each do |d|
                   @client.documents.update_document(d.document_id, d.content, true)
               end
           end
       end
   end
end
