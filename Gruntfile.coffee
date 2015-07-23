module.exports = (grunt) ->
  grunt.initConfig {
    watch:
      scripts:
        files: ['app/**/*.coffee']
        tasks: ['mochaTest']
    mochaTest:
      test:
        options:
          reporter: 'spec'
          require: 'coffee-script/register'
        src: ['app/test/**/*.coffee']
  }

  grunt.loadNpmTasks 'grunt-mocha-test'
  grunt.loadNpmTasks 'grunt-contrib-watch'

  grunt.registerTask 'default', 'watch'
  grunt.registerTask 'test', 'mochaTest'