organization := "crypto-utility"
name := "crypto-utility-protocol"

version := "0.1.0"

scalaVersion := "2.11.8"

val compileDependencies = Seq(

)

val testDependencies = Seq(
  "org.scalatest" %% "scalatest" % "3.0.0" % Test
)

libraryDependencies ++= compileDependencies ++ testDependencies