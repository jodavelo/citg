-- MySQL dump 10.13  Distrib 8.0.35, for Linux (x86_64)
--
-- Host: localhost    Database: citg
-- ------------------------------------------------------
-- Server version	8.0.35-0ubuntu0.22.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `commitment_indicators`
--

DROP TABLE IF EXISTS `commitment_indicators`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `commitment_indicators` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(15) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=259 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `commitment_indicators`
--

LOCK TABLES `commitment_indicators` WRITE;
/*!40000 ALTER TABLE `commitment_indicators` DISABLE KEYS */;
INSERT INTO `commitment_indicators` VALUES (1,'1.0.170.50'),(2,'1.0.171.2'),(3,'1.1.123.166'),(4,'1.1.176.18'),(5,'1.1.187.152'),(6,'1.1.189.58'),(7,'1.2.215.208'),(8,'1.4.199.151'),(9,'1.7.165.3'),(10,'1.7.180.245'),(11,'1.9.70.26'),(12,'1.9.78.242'),(13,'1.9.167.35'),(14,'1.9.212.227'),(15,'1.9.213.114'),(16,'1.10.185.146'),(17,'1.10.192.254'),(18,'1.10.211.15'),(19,'1.12.36.133'),(20,'1.12.36.150'),(21,'1.12.45.168'),(22,'1.12.48.45'),(23,'1.12.53.70'),(24,'1.12.57.134'),(25,'1.12.60.11'),(26,'1.12.60.77'),(27,'1.12.62.80'),(28,'1.12.74.35'),(29,'1.12.77.136'),(30,'1.12.220.34'),(31,'1.12.220.225'),(32,'1.12.222.111'),(33,'1.12.230.13'),(34,'1.12.232.140'),(35,'1.12.232.199'),(36,'1.12.239.227'),(37,'1.12.241.33'),(38,'1.12.243.16'),(39,'1.12.244.43'),(40,'1.12.245.12'),(41,'1.12.253.254'),(42,'1.13.2.214'),(43,'1.13.5.215'),(44,'1.13.6.79'),(45,'1.13.6.110'),(46,'1.13.9.243'),(47,'1.13.17.37'),(48,'1.13.91.106'),(49,'1.13.159.117'),(50,'1.13.162.86'),(51,'1.13.191.30'),(52,'1.13.246.60'),(53,'1.14.8.188'),(54,'1.14.8.251'),(55,'1.14.12.14'),(56,'1.14.18.141'),(57,'1.14.20.119'),(58,'1.14.45.178'),(59,'1.14.47.218'),(60,'1.14.59.212'),(61,'1.14.60.225'),(62,'1.14.66.207'),(63,'1.14.70.219'),(64,'1.14.72.158'),(65,'1.14.77.81'),(66,'1.14.92.22'),(67,'1.14.93.77'),(68,'1.14.93.149'),(69,'1.14.94.199'),(70,'1.14.96.114'),(71,'1.14.96.192'),(72,'1.14.96.240'),(73,'1.14.100.89'),(74,'1.14.103.113'),(75,'1.14.107.89'),(76,'1.14.108.77'),(77,'1.14.108.128'),(78,'1.14.110.251'),(79,'1.14.111.21'),(80,'1.14.136.201'),(81,'1.14.153.90'),(82,'1.14.162.37'),(83,'1.14.190.24'),(84,'1.15.39.93'),(85,'1.15.45.157'),(86,'1.15.48.27'),(87,'1.15.50.28'),(88,'1.15.51.35'),(89,'1.15.59.189'),(90,'1.15.68.215'),(91,'1.15.77.124'),(92,'1.15.80.32'),(93,'1.15.81.234'),(94,'1.15.84.247'),(95,'1.15.84.248'),(96,'1.15.85.24'),(97,'1.15.89.118'),(98,'1.15.91.243'),(99,'1.15.93.245'),(100,'1.15.98.138'),(101,'1.15.108.36'),(102,'1.15.109.89'),(103,'1.15.111.149'),(104,'1.15.114.184'),(105,'1.15.119.157'),(106,'1.15.120.4'),(107,'1.15.122.64'),(108,'1.15.133.14'),(109,'1.15.138.95'),(110,'1.15.150.21'),(111,'1.15.155.17'),(112,'1.15.156.81'),(113,'1.15.178.60'),(114,'1.15.179.181'),(115,'1.15.181.191'),(116,'1.15.181.252'),(117,'1.15.183.137'),(118,'1.15.184.96'),(119,'1.15.189.200'),(120,'1.15.223.195'),(121,'1.15.226.217'),(122,'1.15.229.173'),(123,'1.15.230.22'),(124,'1.15.242.165'),(125,'1.15.247.236'),(126,'1.15.248.71'),(127,'1.20.95.95'),(128,'1.20.137.82'),(129,'1.20.156.196'),(130,'1.20.184.75'),(131,'1.20.199.128'),(132,'1.20.203.95'),(133,'1.20.214.37'),(134,'1.22.54.70'),(135,'1.22.231.87'),(136,'1.28.126.94'),(137,'1.32.20.115'),(138,'1.32.35.159'),(139,'1.32.43.255'),(140,'1.32.59.217'),(141,'1.32.216.76'),(142,'1.33.123.220'),(143,'1.33.217.246'),(144,'1.34.1.31'),(145,'1.34.7.56'),(146,'1.34.7.76'),(147,'1.34.13.171'),(148,'1.34.17.141'),(149,'1.34.18.197'),(150,'1.34.33.235'),(151,'1.34.58.224'),(152,'1.34.70.148'),(153,'1.34.76.249'),(154,'1.34.100.72'),(155,'1.34.102.117'),(156,'1.34.106.61'),(157,'1.34.107.46'),(158,'1.34.127.180'),(159,'1.34.127.198'),(160,'1.34.133.138'),(161,'1.34.134.211'),(162,'1.34.135.116'),(163,'1.34.146.59'),(164,'1.34.170.9'),(165,'1.34.182.81'),(166,'1.34.198.137'),(167,'1.34.204.30'),(168,'1.34.234.1'),(169,'1.36.40.138'),(170,'1.36.126.27'),(171,'1.52.52.252'),(172,'1.52.222.8'),(173,'1.52.225.219'),(174,'1.53.56.100'),(175,'1.53.80.118'),(176,'37.0.8.192'),(177,'37.0.10.28'),(178,'37.0.10.182'),(179,'37.0.11.64'),(180,'37.0.11.78'),(181,'37.0.11.130'),(182,'37.0.11.157'),(183,'37.0.11.224'),(184,'37.1.21.112'),(185,'37.1.202.158'),(186,'37.1.216.152'),(187,'103.13.207.4'),(188,'103.13.207.165'),(189,'103.13.207.217'),(190,'103.13.210.54'),(191,'103.14.8.100'),(192,'103.14.38.98'),(193,'103.14.48.254'),(194,'103.14.49.174'),(195,'103.14.235.70'),(196,'103.15.50.58'),(197,'103.15.74.102'),(198,'103.15.95.127'),(199,'103.15.240.149'),(200,'103.16.62.57'),(201,'103.16.63.22'),(202,'103.16.63.26'),(203,'103.16.132.96'),(204,'103.16.132.100'),(205,'103.16.132.187'),(206,'103.16.136.133'),(207,'103.16.136.149'),(208,'103.16.202.172'),(209,'103.16.202.187'),(210,'103.16.228.20'),(211,'103.17.9.234'),(212,'179.32.33.161'),(213,'179.32.44.155'),(214,'179.32.55.30'),(215,'179.33.186.151'),(216,'179.36.207.165'),(217,'179.38.75.40'),(218,'179.40.46.146'),(219,'179.40.75.1'),(220,'179.40.112.6'),(221,'179.41.2.183'),(222,'179.41.2.196'),(223,'179.41.2.208'),(224,'179.41.26.126'),(225,'179.42.124.80'),(226,'179.42.225.154'),(227,'179.43.96.178'),(228,'179.43.98.221'),(229,'179.43.122.214'),(230,'179.43.127.230'),(231,'179.43.139.10'),(232,'179.43.140.150'),(233,'179.43.142.20'),(234,'179.43.142.43'),(235,'202.96.74.135'),(236,'202.97.173.152'),(237,'202.103.55.32'),(238,'202.104.242.30'),(239,'202.105.13.130'),(240,'202.105.41.26'),(241,'202.105.107.203'),(242,'202.105.107.204'),(243,'216.53.136.100'),(244,'216.53.148.173'),(245,'102.130.113.9'),(246,'103.129.222.46'),(247,'178.128.23.9'),(248,'185.101.21.232'),(249,'1.55.39.38'),(250,'1.116.76.185'),(251,'1.116.76.186'),(252,'1.55.167.233'),(253,'1.55.207.104'),(254,'1.55.209.48'),(255,'1.55.211.227'),(256,'20.163.153.235'),(257,'20.163.158.177'),(258,'20.163.162.74');
/*!40000 ALTER TABLE `commitment_indicators` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `malicious_ip_addresses`
--

DROP TABLE IF EXISTS `malicious_ip_addresses`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `malicious_ip_addresses` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(15) DEFAULT NULL,
  `description` text,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `malicious_ip_addresses`
--

LOCK TABLES `malicious_ip_addresses` WRITE;
/*!40000 ALTER TABLE `malicious_ip_addresses` DISABLE KEYS */;
INSERT INTO `malicious_ip_addresses` VALUES (1,'178.128.23.9','A Network Trojan was detected'),(2,'103.129.222.46','Misc Attack'),(3,'102.130.113.9','Misc Attack'),(4,'185.101.21.232','A Network Trojan was detected'),(5,'1.55.39.38','A Network Trojan was detected'),(6,'1.116.76.185','A Network Trojan was detected'),(7,'1.55.167.233','A Network Trojan was detected'),(8,'1.55.207.104','A Network Trojan was detected'),(9,'1.55.209.48','A Network Trojan was detected'),(10,'1.55.211.227','A Network Trojan was detected'),(11,'20.163.153.235','A Network Trojan was detected'),(12,'20.163.158.177','A Network Trojan was detected'),(13,'20.163.162.74','A Network Trojan was detected');
/*!40000 ALTER TABLE `malicious_ip_addresses` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `positive_negatives`
--

DROP TABLE IF EXISTS `positive_negatives`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `positive_negatives` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(15) DEFAULT NULL,
  `description` text,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `positive_negatives`
--

LOCK TABLES `positive_negatives` WRITE;
/*!40000 ALTER TABLE `positive_negatives` DISABLE KEYS */;
INSERT INTO `positive_negatives` VALUES (1,'102.130.113.9','Misc Attack'),(2,'103.129.222.46','Misc Attack'),(3,'178.128.23.9','A Network Trojan was detected'),(4,'185.101.21.232','A Network Trojan was detected'),(5,'1.55.39.38','A Network Trojan was detected'),(6,'1.116.76.185','A Network Trojan was detected'),(7,'1.116.76.186','A Network Trojan was detected'),(8,'1.55.167.233','A Network Trojan was detected'),(9,'1.55.209.48','A Network Trojan was detected'),(10,'20.163.158.177','A Network Trojan was detected'),(11,'20.163.162.74','A Network Trojan was detected');
/*!40000 ALTER TABLE `positive_negatives` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2023-11-21  1:57:43
