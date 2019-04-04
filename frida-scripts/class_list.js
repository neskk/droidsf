Java.perform(function x() {

  Java.enumerateLoadedClasses({
    "onMatch": function (className) {
      send(className);
    },
    "onComplete": function () {}
  });

});