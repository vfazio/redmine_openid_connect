class CascadeDeleteSessions < ActiveRecord::Migration
	def up
	  change_table :oic_sessions do |t|
		t.remove_references :user, foreign_key: true
		t.references :user, foreign_key: { on_delete: :cascade }
	  end
	end

	def down
	  change_table :oic_sessions do |t|
		t.remove_references :user, foreign_key: { on_delete: :cascade }
		t.references :user, foreign_key: true
	  end
	end
  end
